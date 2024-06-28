
import binascii
import struct
import socket
import random
import time
import machine

from scrivo.tools.tool import launch, asyncio, DataClassArg
from machine import UART

from .config import data_request, data_battery, data_register_master, data_register_slave, panel_slave_addr
from .crc import calc_crc16, check_crc16

from scrivo import logging
log = logging.getLogger("RTU")
log.setLevel(logging.DEBUG)

led = machine.Pin(2, machine.Pin.OUT)

reg_code = {
    0x01: 0,
    0x02: 10001,
    0x03: 40001,
    0x04: 30001,
}

#peer = b'\x24\x68\x28\x04\x70\x0C'  # client MAC address Real Meter


#panel_slave_addr = [1]

def hexh(data,  sep=' '):
    try:
        data = f'{sep}'.join('{:02x}'.format(x) for x in data)
    except Exception as e:
        log.error("HEX: {}".format(e))
    return data

class Solax:
    

    def __init__(self):        
        launch(self._activate)

    async def _activate(self):

        self.panel_uart = UART(1, baudrate=9600, tx=13, rx=14)
        self.panel_swriter = asyncio.StreamWriter(self.panel_uart, {})
        self.panel_sreader = asyncio.StreamReader(self.panel_uart)
        self.panel_slave_addr = panel_slave_addr

        launch(self.panel_receiver)
        
    
    async def panel_receiver(self):
        
        while True:
            try:
                data = b''
                try:  # wait for response and read it
                    starte = time.ticks_us()
                    data = await asyncio.wait_for(self.panel_sreader.read(-1), 1)
                    #data = b'\x01\x03\x00\x0e\x00\x01\xe5\xc9'
                    #print('Data_Solax: {}'.format(data))
                except asyncio.TimeoutError:
                    log.debug('Panel got timeout')
                    await asyncio.sleep(5)
                    # emu for dev
                    # data = self.panel_emu()

                
                if data != b'':
                   # print('data: {}'.format(data))
                    pdu_response = self.panel_request_decode(data)
                    if pdu_response is not None:
                        await self.panel_swriter.awrite(pdu_response)
                        log.debug(f"  Tempo RTU: {time.ticks_diff(time.ticks_us(), starte)}")
            except Exception as e:
                log.error("PANEL: {}".format(e))
            #await asyncio.sleep(1)

    def panel_request_decode(self, request):
        value_byte = None
        # DEBUG
        log.debug(" ")
        log.debug(f" << uart request: {hexh(request)} - {len(request)}")
        

        if len(request) < 8:
            return None

        remote_unit_addr, remote_reg_func, remote_reg_addr = struct.unpack_from('>BBH', request, 0)
            
        if request[0] not in self.panel_slave_addr:
        
            return None

        crc, request_data = check_crc16(request)
        # DEBUG
      #  log.debug(f"       crc check: {hexh(crc)}")

        if crc:
            # Request param
            unit_addr, reg_func, reg_addr, qty = struct.unpack_from('>BBHH', request_data, 0)  # 00: 00 : 00 00 : 00 00
            # DEBUG
        #    log.debug(f"   addr: {unit_addr}, func: {reg_func}, reg_addr: {reg_addr}, qty: {qty} ")

            # Calc offset
            reguest_offset = reg_code[reg_func]+reg_addr
            # DEBUG
        #    log.debug(f"   reguest_offset: {reguest_offset}")

            # Check if reguest exist, that map for request.
            if reguest_offset in data_register_slave:
                data_slave = data_register_slave[reguest_offset]
                master_offset = data_slave["master"]
          #      log.debug(f"   data_slave: {data_slave}")
          #      log.debug(f"   master_offset: {master_offset}")

                # if data exist in data_register_master
                if master_offset in data_register_master:
                    data_master = data_register_master[master_offset]
              #      log.debug(f"   data_master : {data_master }")

                    # DEBUG
              #      log.debug(f"   - alive: {data_master['alive']}")

                    # get value if data alive
                    if data_master["alive"] >= 5:
                        data_master["alive"] -= 1
                        # get value from master record and conver for rigt response
                        if data_slave["act"] is not None:
                            value_byte = self._act(data_master["value"], **data_slave["act"])
                        # get value from master record, that is raw data from device
                        else:
                            value_byte = data_master["raw"]
                            # DEBUG
                            log.debug(f"   Modbus raw: {hexh(value_byte)}")
                            return value_byte

                # if -1, get value from action == emulate response
                elif master_offset == -1:
                    value_byte = self._act(**data_slave["act"])

            return self.make_pdu_response(unit_addr, reg_func, value_byte)

    

    def make_pdu_response(self, unit_addr, reg_func, value_byte):
        if value_byte is not None:
            # DEBUG
           # log.debug(f"  Modbus data:      {hexh(value_byte)}")

            modbus_pdu = bytearray()
            modbus_pdu.append(unit_addr)                    # unit_addr
            modbus_pdu.extend(struct.pack('B', reg_func))   # reg_func
            modbus_pdu.extend(value_byte)                   # value_byte
            modbus_pdu.extend(calc_crc16(modbus_pdu))       # crc

            # DEBUG
          #  log.debug(f"  Modbus Pdu: {hexh(modbus_pdu)}")

            return modbus_pdu
        

    def _act(self, value=None, **act):
        # DEBUG
        log.debug(f"   act : {act}")

        if value is None:
            value = act["value"]
        # DEBUG
      #  log.debug(f"   value: {value}")

        # pack value to bytes
        if "pack" in act:
            # convert value
            if "data_type" in act:
                data_type = act["data_type"]
                if data_type == "int":
                    value = int(value)
                if data_type == "float":
                    value = float(value)
                value * act["scale"]
                # DEBUG
              #  log.debug(f"   value convert: {value}")

            value_byte = struct.pack(act["pack"], value)
            # pack to len_byte+value_byte
            value = struct.pack("B", len(value_byte)) + value_byte
            # DEBUG
           # log.debug(f"   act bytes: {hexh(value)}")

        if "unpack" in act:
            value = struct.unpack(act["unpack"], value)[0]
            # DEBUG
         #   log.debug(f"   act value: {value}")

        return value                  
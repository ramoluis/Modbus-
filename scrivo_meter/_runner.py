
import binascii
import struct
import socket
#import wiznet5k_socket as socket
import random
import time
import machine
#import aioespnow
#from uModBus.TCP import uModBusTCP as TCP
from machine import UART
#from uModBus import TCP

from scrivo.tools.tool import launch, asyncio, DataClassArg
from .crc import calc_crc16, check_crc16

from scrivo import logging

log = logging.getLogger("MODBUS")
log.setLevel(logging.DEBUG)

led = machine.Pin(2, machine.Pin.OUT)


def hexh(data,  sep=' '):
    try:
        data = f'{sep}'.join('{:02x}'.format(x) for x in data)
    except Exception as e:
        log.error("HEX: {}".format(e))
    return data

data_request = {
    "Victron": {
        "addr": 100,
        "func": 3,
        "start_reg": 843,
        "qty_reg": 1,
        "alive": 0,
        "raw": 0x00,
    }
}


#TODO: move to json config
data_register_master = {
    30013: {
        "alive": 0,
        "raw": b'\x00',
        "value": 0,
        "act": {"unpack": ">f", "scale": 1, "unit": "W", },
    },
    48193: {
        "alive": 0,
        "raw": binascii.unhexlify("01030c436a4ccd000000000000000083ec"),
        "value": 0,
        "act": None,
    },
    42601: {
        "alive": 0,
        "raw": b'\x00',
        "value": 0,
        "act": {"unpack": ">h", "scale": 1, "unit": "W", },
    },
    
}


#TODO: move to json config
data_register_slave = {

    # solax ask from: func 03 , 00 0e = 14+1 = offset 40015
    40015: {
        "master": 42601, #30013,
        "func": 0x03,
        "act": {"pack": ">h", "scale": 1, "data_type": "int"}
    },

    # solax ask from: func 03,  00 0b = 11+1 = offset 40012
    40012: {
        "master": -1,
        "func": 0x03,
        "act": {"pack": ">h", "scale": 1, "value": 0}
    },

    # solax ask from: func 03, 8+1 = offset 40009
    40009: {
        "master": -1,
        "func": 0x03,
        "act": {"pack": ">h", "scale": 1, "value": 0}
    },

    48193: {
        "master": 48193,
        "func": 0x03,
        "act": None
    },


}

reg_code = {
    0x01: 0,
    0x02: 10001,
    0x03: 40001,
    0x04: 30001,
}

peer = b'\x24\x68\x28\x04\x70\x0C'  # client MAC address Real Meter


panel_slave_addr = [1]


class Runner:
    

    def __init__(self, slave_port=502, timeout=5):
        
        slave_ip = '192.168.53.95'
        self._sock = socket.socket()
        self._sock.connect(socket.getaddrinfo(slave_ip, slave_port)[0][-1])     
        self._sock.settimeout(timeout)
        
        log.info("Module: Victron ")
          
        launch(self._activate)


    async def _activate(self):
        
        slave_ip = '192.168.53.95'
        
        await asyncio.sleep(2)       
        self.request_data = []
        for key, value in data_request.items():
            self.request_data.append(DataClassArg(name=key, **value))

        self.panel_uart = UART(1, baudrate=9600, tx=13, rx=14)
        self.panel_swriter = asyncio.StreamWriter(self.panel_uart, {})
        self.panel_sreader = asyncio.StreamReader(self.panel_uart)
        self.panel_slave_addr = panel_slave_addr

        launch(self.victron)
        launch(self.panel_receiver)
        
    def make_request(self, request):
        
        quantity = request.qty_reg
        request_pdu = struct.pack('>BBHH', request.addr, request.func, request.start_reg, quantity)
        #log.debug(f"  Request : {request_pdu}")
        
        # debug
        log.debug(f"  Pdu Reguest : {hexh(request_pdu)}")
        print('Pdu Reguest: {}'.format(request_pdu))
        modbus_pdu = bytearray()
        modbus_pdu.extend(request_pdu)
        modbus_pdu.extend(calc_crc16(request_pdu))
        # debug
        log.debug(f"  Pdu UART : {hexh(modbus_pdu)}")
        log.debug(" ")

        return modbus_pdu
    
    async def victron(self):
         log.info("Module: Victron ")
         log.debug(" ")
         
         slave_id = 100
         quantity = 1
         starting_address = 843
         MBAP_HDR_LENGTH = 0x07
         ERROR_BIAS = 0x80
         function_code = 0x03
         
         #print('ModBus slave_id: {}'.format(slave_id))
         #print('ModBus Quantidade: {}'.format(quantity))
         #print('ModBus starting_address: {}'.format(starting_address))
         
         if not (1 <= quantity <= 125):
             raise ValueError('invalid number of holding registers')
         modbus_pdu = struct.pack('>BHH', 3, starting_address, quantity)
         #print('ModBus_PDU: {}'.format(modbus_pdu))
         trans_id = random.randint(0, 65535) & 0xFFFF
         mbap_hdr = struct.pack('>HHHB', trans_id, 0, len(modbus_pdu) + 1, slave_id)
         #print('ModBus_trans_id: {}'.format(trans_id))
         #print('ModBus_mbap_hdr: {}'.format(mbap_hdr))
         
         while True:
            start = time.ticks_us()
            for request in self.request_data:
                request.alive -= 1
             #   uart_pdu = self.make_request(request)
             #   log.debug(f"uart_pdu: {uart_pdu}")
             #   log.debug(f"uart_pdu_xh: {hexh(uart_pdu)}")
             #   if uart_pdu is not None:
                    #print('uart_pdu: {}'.format(uart_pdu))
              #      print('send request to unit: ')
                   # await self.panel_swriter.awrite(uart_pdu)
                led.value(1)    
                self._sock.send(mbap_hdr + modbus_pdu)
                #print('ModBus_sock.send: {}'.format(mbap_hdr + modbus_pdu))
                #await self.panel_swriter.awrite(mbap_hdr + modbus_pdu)
                
                try:  # wait for response and read it
                    response = self._sock.recv(256)
                    led.value(0)
                    #print('response: {}'.format(response))
                except asyncio.TimeoutError:
                    log.debug('################  Cerbo got timeout  ##########')
                    await asyncio.sleep(5)
                    
                rec_tid, rec_pid, rec_len, rec_uid, rec_fc = struct.unpack('>HHHBB', response[:MBAP_HDR_LENGTH + 1])
        
                count = True
                if (trans_id != rec_tid):
                    raise ValueError('wrong transaction Id')

                if (rec_pid != 0):
                    raise ValueError('invalid protocol Id')

                if (slave_id != rec_uid):
                    raise ValueError('wrong slave Id')

                if (rec_fc == (function_code + ERROR_BIAS)):
                    raise ValueError('slave returned exception code: {:d}'.format(rec_fc))
                
               # log.debug(f"rec_uid: {rec_uid}, reg_func: {rec_fc}, rec_tid: {rec_tid}")

                hdr_length = (MBAP_HDR_LENGTH + 2) if count else (MBAP_HDR_LENGTH + 1)
                response = response[hdr_length:]
                #print('Register_response: {}'.format(response))
                
                #register_value = self._to_short(response, signed) 
                signed=True
                response_quantity = int(len(response) / 2)
                #print('ModBus_response_quantity: {}'.format(response_quantity))
                fmt = '>' + (('h' if signed else 'H') * response_quantity)
                #print('Register_fmt: {}'.format(fmt))
                register_value = struct.unpack(fmt, response)
                #print('Register_value: {}'.format(register_value))
                log.debug(f"Register_value: {register_value}")
                #log.debug(f"Register_value_hex: {hexh(register_value)}")
                #print('Registo_3: {}'.format(register_value[3:]))
                
                val_data = response
                
                request_offset = reg_code[function_code] + starting_address
                #log.debug(f"Remote: offset: {request_offset}")
                                
                if request_offset in data_register_master:
                    data_master = data_register_master[request_offset]
                   # log.debug(f"Data_master IF: {data_master}")
                else:
                    data_register_master[request_offset] = {}
                    data_master = data_register_master[request_offset]
                    data_master['act'] = None
                  #  log.debug(f"Data_master ELSE: {data_master}")
                
                log.debug(f" >> recv victron: {hexh(response)}")
                data_master["alive"] = 10
                data_master["raw"] = response
                
                if data_master["act"] is not None:
                    data_master["value"] = self._act(data_master["raw"], **data_master["act"])
                                    
               # log.debug(f"Data_master: {data_master}")

                log.debug(" ")
                request.alive = 10
                request.raw = response  # response full.
                #log.debug(f"request: {request}")
                log.debug(f" Tempo TCP: {time.ticks_diff(time.ticks_us(), start)}")
                #print('Tempo: ',time.ticks_diff(time.ticks_us(), start))
           
            await asyncio.sleep(0.1)


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

    def _act(self, value=None, **act):
        # DEBUG
       # log.debug(f"   act : {act}")

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

                    
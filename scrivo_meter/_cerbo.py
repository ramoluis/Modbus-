
import struct
import binascii
import socket
import random
import time
import machine

from scrivo.tools.tool import launch, asyncio, DataClassArg
#from machine import UART

from .config import data_request, data_battery, data_register_master, data_register_slave, panel_slave_addr
from .crc import calc_crc16, check_crc16

from scrivo import logging
log = logging.getLogger("MODBUS")
log.setLevel(logging.DEBUG)

led = machine.Pin(2, machine.Pin.OUT)

reg_code = {
    0x01: 0,
    0x02: 10001,
    0x03: 40001,
    0x04: 30001,
}

# = b'\x24\x68\x28\x04\x70\x0C'  # client MAC address Real Meter


#panel_slave_addr = [1]

trans_id = ""

def hexh(data,  sep=' '):
    try:
        data = f'{sep}'.join('{:02x}'.format(x) for x in data)
    except Exception as e:
        log.error("HEX: {}".format(e))
    return data

class Cerbo:
    

    def __init__(self, slave_port=502, timeout=5):
        
        slave_ip = '192.168.53.95'
        self._sock = socket.socket()
        self._sock.connect(socket.getaddrinfo(slave_ip, slave_port)[0][-1])     
        self._sock.settimeout(timeout)
        
        log.info("Module: Victron ")
          
        launch(self._activate)


    async def _activate(self):
                
        await asyncio.sleep(2)       
        self.request_data = []
        for key, value in data_request.items():
            self.request_data.append(DataClassArg(name=key, **value))
        
        self.data_battery = []
        for key, value in data_battery.items():
            self.data_battery.append(DataClassArg(name=key, **value))

        launch(self.victron)
        
    
    def modbus_request(self, request):
        global trans_id
        quantity = request.qty_reg
        if not (1 <= quantity <= 125):
            raise ValueError('invalid number of holding registers')
        modbus_pdu = struct.pack('>BHH', request.func, request.start_reg, quantity)
        trans_id = random.randint(0, 65535) & 0xFFFF
        mbap_hdr = struct.pack('>HHHB', trans_id, 0, len(modbus_pdu) + 1, request.addr)
        return (mbap_hdr + modbus_pdu)
    
    def parse_response(self, request, data):
        
        global data_reg

        MBAP_HDR_LENGTH = 0x07
        ERROR_BIAS = 0x80

        rec_tid, rec_pid, rec_len, rec_uid, rec_fc = struct.unpack('>HHHBB', data[:MBAP_HDR_LENGTH + 1])
        count = True
        if (trans_id != rec_tid):
            raise ValueError('wrong transaction Id')
        if (rec_pid != 0):
            raise ValueError('invalid protocol Id')
        if (request.addr != rec_uid):
            raise ValueError('wrong slave Id')
        if (rec_fc == (request.func + ERROR_BIAS)):
            raise ValueError('slave returned exception code: {:d}'.format(rec_fc))
        #log.debug(f"rec_uid: {rec_uid}, reg_func: {rec_fc}, rec_tid: {rec_tid}")

        hdr_length = (MBAP_HDR_LENGTH + 2) if count else (MBAP_HDR_LENGTH + 1)
        data = data[hdr_length:]
        #print('Register_data: {}'.format(data))
        #log.debug(f"Data_hex: {hexh(data)}")
        #register_value = self._to_short(data, signed) 
        signed=True
        data_quantity = int(len(data) / 2)
        #print('ModBus_data_quantity: {}'.format(data_quantity))
        fmt = '>' + (('h' if signed else 'H') * data_quantity)
        #print('Register_fmt: {}'.format(fmt))
        register_value = struct.unpack(fmt, data)
        #data_reg = register_value
        #print('Register_value: {}'.format(register_value))
        log.debug(f"Register_value: --> {register_value[0]}")
        log.debug(f"adress_reg: --> {request.start_reg}")
        #print('Registo_3: {}'.format(register_value[3:]))        
        #val_data = data
        if request.start_reg == 843:
            print('### Bateria ###')
            data_reg = register_value
            return True
            
        if data_reg[0] < 100 and request.start_reg == 820:
            print('### EDP e Bateria < 100% ###')
            data = b'\x00\x00'
            log.debug(f"Data_hex: {hexh(data)}")
            log.debug(f"Data_reg: --> {data[0]}")
        
        self.regist_data(request, data)
        
        return True
        
    
    def regist_data(self, request, data):
        
        #request_offset = reg_code[function_code] + starting_address
        #request_offset = reg_code[request.func] + request.addr
        request_offset = reg_code[request.func] + request.start_reg
        log.debug(f"Remote: offset: {request_offset}")
                                       
        if request_offset in data_register_master:
            data_master = data_register_master[request_offset]
            log.debug(f"Data_master IF: {data_register_master[request_offset]}")
        else:
            data_register_master[request_offset] = {}
            data_master = data_register_master[request_offset]
            data_master['act'] = None
            log.debug(f"Data_master ELSE: {data_master['act']}")
                
        #log.debug(f" >> recv victron: {hexh(data)}")
        data_master["alive"] = 10
        data_master["raw"] = data
                
        if data_master["act"] is not None:
            data_master["value"] = self._act(data_master["raw"], **data_master["act"])                        
            log.debug(f"Data_master: {data_master["value"]}")
            
        log.debug(f"Data_master_Alive: {data_master["alive"]}")
        log.debug(f"Data_master_Raw: {data_master["raw"]}")
        log.debug(f"Data_master_Value: {data_master["value"]}")
        log.debug(f"Data_master_Act: {data_master["act"]}")

        #log.debug(" ")
                
    async def victron(self):
         log.info("Module: Victron ")
         log.debug(" ")
         time_bat = 0
         firt_cicle = 1
         firt_cicle_edp = 1
         bat_charge = 0
                           
         while True:
            start = time.ticks_us()
            #log.debug(f"  time_bat : {(time_bat)}")
            log.debug(f" Tempo Bateria: {time.ticks_diff(time.ticks_us(), time_bat)}")
            if (time.ticks_diff(time.ticks_us(), time_bat) > 300000000) or firt_cicle:
                led.value(1)
                time_bat = time.ticks_us()
                log.info("Module: Victron BAT ")
                #self.read_edp()
                for request_bat in self.data_battery:
                    request_bat.alive -= 1
                    modbus_tcp = self.modbus_request(request_bat)
                    #led.value(1)
                    # send request to unit
                    self._sock.send(modbus_tcp)
                    # wait for response and read it
                    try:  
                        data_bat = self._sock.recv(256)
                        led.value(0)
                        #print('data_bat: {}'.format(data_bat))
                    except asyncio.TimeoutError:
                        await asyncio.sleep(5)
                    
                    if self.parse_response(request_bat, data_bat):
                        request_bat.alive = 10
                        request_bat.raw = data_bat  # response full.
                        #log.debug(f"request_bat: {request_bat.raw}")
                firt_cicle = 0
               # print("%.1f" % data_reg)
               # log.debug(f"Bateria SOC: {data_reg}%")
               # print(data_reg * 2)
                bat_charge = int(data_reg[0]) #(59,)
                firt_cicle_edp = 1
            
            log.debug(f"  bat_charge : {(bat_charge)}")
            
            if bat_charge > 50 or firt_cicle_edp:
                firt_cicle_edp = 0
                for request in self.request_data:
                    request.alive -= 1
                    log.info("Module: Victron EDP ")
    
                    modbus_tcp = self.modbus_request(request)
                    led.value(1)
                    # send request to unit
                    self._sock.send(modbus_tcp)
                    # wait for response and read it
                    try:  
                        data = self._sock.recv(256)
                        led.value(0)
                        #print('response: {}'.format(response))
                    except asyncio.TimeoutError:
                        log.debug('################  Cerbo got timeout  ##########')
                        await asyncio.sleep(5)
                    
                    if self.parse_response(request, data):
                        request.alive = 10
                        request.raw = data  # response full.
                    
                        #log.debug(f"request: {request.raw}")
                    
            log.debug(f" Tempo TCP: {time.ticks_diff(time.ticks_us(), start)}")
            #print('Tempo: ',time.ticks_diff(time.ticks_us(), start))
            log.debug(" ##### ")
           
            await asyncio.sleep(10)


    def _act(self, value=None, **act):
        # DEBUG
        log.debug(f"   act : {act}")

        if value is None:
            value = act["value"]
        # DEBUG
        log.debug(f"   value: {value}")

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
                log.debug(f"   value convert: {value}")

            value_byte = struct.pack(act["pack"], value)
            # pack to len_byte+value_byte
            value = struct.pack("B", len(value_byte)) + value_byte
            # DEBUG
            log.debug(f"   act bytes: {hexh(value)}")

        if "unpack" in act:
            value = struct.unpack(act["unpack"], value)[0]
            # DEBUG
            log.debug(f"   act value: {value}")

        return value


                    
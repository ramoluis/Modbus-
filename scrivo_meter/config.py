import binascii

data_request = {
    "Victron": {
        "addr": 100,
        "func": 3,
        "start_reg": 820,
        "qty_reg": 1,
        "alive": 0,
        "raw": 0x00,
    },
}

data_battery = {
    "Bateria": {
        "addr": 100,
        "func": 3,
        "start_reg": 843,
        "qty_reg": 1,
        "alive": 0,
        "raw": 0x00,
    },
}

#TODO: move to json config  42601
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
    40821: {
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
        "master": 40821, #30013,
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

panel_slave_addr = [1]

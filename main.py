#from wiznet5k import WIZNET5K
#from machine import Pin, SPI
#import wiznet5k_socket as socket
#import sma_esp32_w5500_requests as requests
import uasyncio as asyncio
import _thread
import machine
import network
from scrivo import logging

log = logging.getLogger('MAIN')
logging.basicConfig(level=logging.INFO)

storage_dir = "."

time_bat = 0

#spi = SPI(2)
#cs = Pin(5,Pin.OUT)
#rst=Pin(34)
#nic = WIZNET5K(spi,cs,rst)



#print("Chip Version:", nic.chip)
#print("MAC Address:", [hex(i) for i in nic.mac_address])
#print("My IP address is:", nic.pretty_ip(nic.ip_address))
#print("IP lookup google.com: %s" %nic.pretty_ip(nic.get_host_by_name("google.com")))
#print("My nic.regs is:", socket.socket())
#print("My nic.regs is:",socket.getaddrinfo(slave_ip, slave_port))

# Initialize a requests object with a socket and ethernet interface
#requests.set_socket(socket, nic)

print("Done!")

# WDT
async def run_wdt():
    import gc
    wdt = machine.WDT(timeout=12000)
    print("WDT RUN")
    while True:
        wdt.feed()

        gc.collect()
        # print("WDT RESET")
        await asyncio.sleep(5)
# Core
def core():
    # VFS SIZE
    fs_stat = uos.statvfs(storage_dir)
    fs_size = fs_stat[0] * fs_stat[2]
    fs_free = fs_stat[0] * fs_stat[3]
    log.info("File System Size {:,} - Free Space {:,}".format(fs_size, fs_free))

    part_name = uos.getcwd()
    log.info("PartName: {}".format(part_name))


# Lloader
async def loader():
    try:
        from scrivo_meter._runner import Runner
        log.info("Module: Run")
        meter = Runner()
    except Exception as e:
        log.error(f"Module: {e}")
        
async def loader2():
    try:
        from scrivo_meter._cerbo import Cerbo
        log.info("Module: Run2")
        vectron = Cerbo()
    except Exception as e:
        log.error(f"Module: {e}")
        
async def loader3():
    try:
        from scrivo_meter._solax import Solax
        log.info("Module: Run3")
        solar = Solax()
    except Exception as e:
        log.error(f"Module: {e}")


def main():

    # Activate Core
    core()


    # AsyncIO in thread
    loop = asyncio.get_event_loop()
    _ = _thread.stack_size(8 * 1024)
    _thread.start_new_thread(loop.run_forever, ())

    # Run Loader Task
    loop.create_task(run_wdt())
    loop.create_task(loader2())
    loop.create_task(loader3())


if __name__ == '__main__':
    print("MAIN")
    main()        
        
        
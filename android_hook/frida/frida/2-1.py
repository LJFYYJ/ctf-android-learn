import time
import frida

def my_message_handler(message, payload):
    print(message)
    print(payload)

device = frida.get_usb_device()
pid = device.spawn(["com.example.testfrida2"])
device.resume(pid)
time.sleep(1)
session = device.attach(pid)
with open("2-1.js") as f:
    script = session.create_script(f.read())
script.on("message", my_message_handler)
script.load()

command = ""
while 1 == 1:
    command = input("Enter command:\n1: Exit\n2: Call secret function\nchoice:")
    if command == "1":
        break
    elif command == "2": #在这里调用
        script.exports.callsecretfunction()
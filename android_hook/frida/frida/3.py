import time
import frida
import base64

def my_message_handler(message, payload):
    if message["type"] == "send" and message["payload"]:
        data = message["payload"].split(":")[1].strip()
        print('message:', message)
        data = base64.decodebytes(data.encode('utf-8'))
        data = str(data)
        user, pw = data.split(":")
        data = base64.encodebytes(("admin" + ":" + pw).encode())
        data = str(data)
        print("encoded data:", data)
        script.post({"my_data": data})  # 将JSON对象发送回去
        print("Modified data sent")

device = frida.get_usb_device()
pid = device.spawn(["com.example.testfrida2"])
device.resume(pid)
time.sleep(1)
session = device.attach(pid)
try:
    with open("3.js") as f:
        script = session.create_script(f.read())
    script.on("message", my_message_handler)  # 注册消息处理函数
    script.load()
except Exception as e:
    print(e)

input()
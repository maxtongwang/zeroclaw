# ZeroClaw Pico firmware — serial JSON protocol handler
# MicroPython — Raspberry Pi Pico (RP2040)
#
# Wire protocol:
#   Host → Device:  {"cmd":"gpio_write","params":{"pin":25,"value":1}}\n
#   Device → Host:  {"ok":true,"data":{"pin":25,"value":1,"state":"HIGH"}}\n

import sys
import json
from machine import Pin

# Onboard LED — GPIO 25 on Pico 1
led = Pin(25, Pin.OUT)

def handle(msg):
    cmd    = msg.get("cmd")
    params = msg.get("params", {})

    if cmd == "ping":
        # data.firmware must equal "zeroclaw" for ping_handshake() to pass
        return {"ok": True, "data": {"firmware": "zeroclaw", "version": "1.0.0"}}

    elif cmd == "gpio_write":
        pin_num = params.get("pin")
        value   = params.get("value")
        if pin_num is None or value is None:
            return {"ok": False, "error": "missing pin or value"}
        # Normalize value: accept bool or int, must resolve to 0 or 1.
        if isinstance(value, bool):
            value = int(value)
        if not isinstance(value, int) or value not in (0, 1):
            return {"ok": False, "error": "invalid value: must be 0 or 1"}
        if pin_num == 25:
            led.value(value)
        else:
            Pin(pin_num, Pin.OUT).value(value)
        state = "HIGH" if value == 1 else "LOW"
        return {"ok": True, "data": {"pin": pin_num, "value": value, "state": state}}

    elif cmd == "gpio_read":
        pin_num = params.get("pin")
        if pin_num is None:
            return {"ok": False, "error": "missing pin"}
        value = led.value() if pin_num == 25 else Pin(pin_num, Pin.IN).value()
        state = "HIGH" if value == 1 else "LOW"
        return {"ok": True, "data": {"pin": pin_num, "value": value, "state": state}}

    else:
        return {"ok": False, "error": "unknown cmd: {}".format(cmd)}

while True:
    try:
        line = sys.stdin.readline().strip()
        if not line:
            continue
        msg    = json.loads(line)
        result = handle(msg)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))

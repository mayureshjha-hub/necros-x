"""
NECROS X — Raspberry Pi Hardware Controller
Wiring:
  GPIO17 → 220Ω → GREEN LED → GND
  GPIO27 → 220Ω → AMBER LED → GND
  GPIO22 → 220Ω → RED   LED → GND
  Pin 6  → GND (common)
"""
import asyncio

GPIO_AVAILABLE = False
PIN_GREEN = 17
PIN_AMBER = 27
PIN_RED   = 22

try:
    import RPi.GPIO as GPIO
    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    for pin in [PIN_GREEN, PIN_AMBER, PIN_RED]:
        GPIO.setup(pin, GPIO.OUT)
        GPIO.output(pin, GPIO.LOW)
    GPIO_AVAILABLE = True
    print("[NECROS] GPIO hardware active — LED panel ready")
except Exception:
    print("[NECROS] No GPIO — software mode")


def led_set(green=False, amber=False, red=False):
    if not GPIO_AVAILABLE:
        return
    import RPi.GPIO as GPIO
    GPIO.output(PIN_GREEN, GPIO.HIGH if green else GPIO.LOW)
    GPIO.output(PIN_AMBER, GPIO.HIGH if amber else GPIO.LOW)
    GPIO.output(PIN_RED,   GPIO.HIGH if red   else GPIO.LOW)


async def led_blink(color="red", times=3, interval=0.25):
    if not GPIO_AVAILABLE:
        return
    import RPi.GPIO as GPIO
    pin = {"green": PIN_GREEN,
           "amber": PIN_AMBER,
           "red":   PIN_RED}.get(color, PIN_RED)
    for _ in range(times):
        GPIO.output(pin, GPIO.HIGH)
        await asyncio.sleep(interval)
        GPIO.output(pin, GPIO.LOW)
        await asyncio.sleep(interval)


async def led_sequence_scan():
    for _ in range(6):
        led_set(green=True)
        await asyncio.sleep(0.3)
        led_set()
        await asyncio.sleep(0.3)


async def led_sequence_zombie():
    for _ in range(4):
        led_set(red=True, amber=True)
        await asyncio.sleep(0.2)
        led_set()
        await asyncio.sleep(0.2)
    led_set(red=True)


async def led_sequence_breach():
    for _ in range(8):
        led_set(red=True)
        await asyncio.sleep(0.1)
        led_set()
        await asyncio.sleep(0.1)
    led_set(red=True)


async def led_sequence_honeypot():
    for _ in range(6):
        led_set(green=True)
        await asyncio.sleep(0.12)
        led_set()
        await asyncio.sleep(0.12)
    led_set(green=True)


async def led_test():
    led_set(green=True);  await asyncio.sleep(0.5)
    led_set(amber=True);  await asyncio.sleep(0.5)
    led_set(red=True);    await asyncio.sleep(0.5)
    led_set(green=True, amber=True, red=True)
    await asyncio.sleep(0.5)
    led_set()
    await asyncio.sleep(0.2)
    led_set(green=True)


def cleanup():
    if GPIO_AVAILABLE:
        import RPi.GPIO as GPIO
        led_set()
        GPIO.cleanup()
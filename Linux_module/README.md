Features
--

- When loaded, the module starts invisible;

- Hide/unhide any process via Netlink (`./ctl hide <PID>`);

- Make the module become (in)visible via Netlink (`./ctl modinvis`);


Install
--

Verify if the kernel is 2.6.x/3.x/4.x/5.x/6.x
```
uname -r
```

Enter the folder
```
cd Linux_module
```

Compile
```
make
gcc -Wall -Wextra -o ctl user_space.c
```

Load the module(as root)
```
insmod hide_proc.ko
```

Uninstall
--

The module starts invisible, to remove you need to make it visible
```
./ctl modinvis
```

Then remove the module(as root)
```
rmmod hide_proc
```


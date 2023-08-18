ml.exe /c /Cp .\decoder.asm

link /SUBSYSTEM:console /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.19041.0\um\x86\kernel32.lib" /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.19041.0\um\x86\shell32.lib" .\decoder.obj /entry:main
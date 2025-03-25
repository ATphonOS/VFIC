## VFIC - Version File Integrity Check

Verifies the integrity of the code and its associated version by validating the integrity of all files composing the program or firmware using their SHA-1 hash.


## Compile

To compile download the [source code](https://github.com/ATphonOS/VFIC/archive/refs/heads/main.zip) and unzip. 

Option 1 (generates a single exe file):

```Python
pyinstaller --onefile --windowed --icon=icon/logo_app.png --add-data "icon/logo_app.png;icon" 
--name Version File Integrity Check VFIC.py
```

Option 2:

Compile command (create a folder with the executable and all dependencies):

```Python
pyinstaller --onedir --windowed --icon=icon/logo_app.png --add-data "icon/logo_app.png;icon" 
--name Version File Integrity Check VFIC.py
```


## Usage

![VFIC1](https://github.com/user-attachments/assets/b6df1496-6a6a-4edb-9680-c31c4b12d752)


1. Open the directory containing the code files you want to check. The directory should also contain the ***file_hashes.txt*** file.

 ***file_hashes.txt*** contains the name of all files, their associated hash and version. 
 
2. Click Check Integrity to start the check.
3. Once the process is complete, the program returns the result, the associated version, and if the result is correct, it generates a TXT file with a log containing the scanned files and their hashes. If there is an error in the process, a file is missing, or extra files are found, an error message will appear.
 
 ![VFIC2](https://github.com/user-attachments/assets/23c3f14f-6acc-44cb-8615-37846fba2bbc)


## Documentation

The documentation is generated with Pydoc and is included in the docs directory. To access the index, module index, keywords, and topics, you need to run Pydoc server.

```Python
python -m pydoc -p 8000
```

While keeping the server running, we open any HTML file included in the 'docs' directory, making those links accessible.

To generate the documentation again, it is necessary to run the Pydoc server with the previous command, open a new terminal (CMD), and execute the following command:

> You must have wget in the same directory as the code. Version 1.21.4 x64 for Windows included in the repository. Download [wget](https://eternallybored.org/misc/wget/).


```Python
wget -i modules.txt -P docs -p -k
```

**-i modules.txt**: Read the URLs from the file modules.txt.

**-P docs**: Save the files in a folder called docs (you can change the name).

**-p**: Download the necessary resources (like CSS).

**-k**: Convert the links so they work locally.

***Currently Windows-only***

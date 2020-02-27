try:
    import sys
    import hashlib
    import json
    import os
    import requests
    from PIL import Image, ImageTk
    from tkinter import messagebox
    from tkinter import filedialog
    import tkinter.ttk as ttk
    import tkinter as tk
    import time
    from datetime import datetime
    import pygubu as pg
except ImportError:
    print("Missing Packages")
    sys.exit(0)

# globals #
path = ""
active_log = []
screen = tk.Tk()
w = 1000  # width for the Tk root
h = 500  # height for the Tk root
ws = screen.winfo_screenwidth()  # width of the screen
hs = screen.winfo_screenheight()  # height of the screen

# calculate x and y coordinates for the Tk screen window
x = (ws/2) - (w/2)
y = (hs/2) - (h/2)
screen.geometry('%dx%d+%d+%d' % (w, h, x, y))
tree = ""


class VirusTotal:
    # loads configuration
    def __init__(self):
        self.res_ok = 200
        # api license
        self.API_KEY = 'd77a04a643e6403195ebda7026ec1ae6891efad207ea9272b1b3b0e0c6e9fe3b'
        self.API_URL = 'https://www.virustotal.com/vtapi/v2/'

    # return the description of the error
    def handle_http_erros(self, code):
        if code == 404:
            return '[Error 404] Something went wrong.'
        elif code == 403:
            return '[Error 403] The api-key you are using, does not have permissions to make that call.'
        elif code == 204:
            return '[Error 204] The quota limit has exceeded, please wait and try again soon.'
        elif code == 400:
            return 'Bad request. Your request was somehow incorrect.'
        else:
            return 'Unkown error.'

    # getting the result for 1 file
    def getfile(self, file):
        if os.path.isfile(file):
            f = open(file, 'rb')
            file = hashlib.sha256(f.read()).hexdigest()
            f.close()
        api = "file/report"
        params = {"resource": file, "apikey": self.API_KEY}
        return requests.post(self.API_URL + api, params=params)

    # getting the results for the selected files
    def get_files(self, files_names):
        result = []
        for filename in files_names:
            check = -2
            while check == -2:
                res = self.getfile(filename)
                if res.status_code != self.res_ok:
                    msg = self.handle_http_erros(res.status_code)
                    if res.status_code == 204:      # checking if we pass the limit
                        messagebox.showerror('Max Capacity', 'Have to wait 1 minute, please wait')
                        time.sleep(60)
                        res = self.getfile(filename)
                    else:
                        messagebox.showerror('Error' + res.status_code, msg)
                        sys.exit(0)
                res = json.loads(res.text)
                check = res['response_code']
            res = res['scans']
            res_scan = list(filter((lambda x: res[x] is None), res))
            if len(res_scan) > 0:
                result.append((filename, True))
            else:
                result.append((filename, False))
        return result

    # sending the selected files for scanning
    def send_files(self, filenames):
        """
        Send files to scan
        @param filenames: list of target files
        """
        url = self.API_URL + "file/scan"
        attr = {"apikey": self.API_KEY}

        for filename in filenames:
            files = {"file": open(filename, 'rb')}
            res = requests.post(url, data=attr, files=files)
            if res.status_code != self.res_ok:
                msg = self.handle_http_erros(res.status_code)
                if res.status_code == 204:          # checking if we pass the limit
                    self.handle_http_erros(res.status_code)
                    messagebox.showerror('Max Capacity', 'Have to wait 1 minute, please wait')
                    time.sleep(60)
                    requests.post(url, data=attr, files=files)
                else:
                    messagebox.showerror('Error' + res.status_code, msg)
                    sys.exit(0)
        return filenames

    # main function of the class that will use the other functions for scanning
    def scanner(self):
        global path
        if path == "":              # make sure we choose path
            messagebox.showerror('Missing Path', 'Have to choose Path first')
            return
        tree.delete(*tree.get_children())                   # deleting the old chart
        list_files = path
        list_files = self.send_files(list_files)
        res = self.get_files(list_files)
        self.insert_tree(res)
        path = ""

    # inserting to tree the files with the result of the scanning
    def insert_tree(self, res):
        global screen
        global tree
        global active_log
        for i in range(len(res)):
            tmp = res[i]
            if not tmp[1]:
                msg = 'Ok'
            else:
                msg = 'Infected!'
            tree.insert("", i, text=os.path.basename(tmp[0]), values=msg)
            now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            active_log.append((os.path.basename(tmp[0]), msg, now))
        screen.config()

    # function for choosing path
    def open_file(self):
        global screen
        global path
        rep = filedialog.askopenfilenames(parent=screen, initialdir=os.getcwd(), filetypes=[("All files", "*")])
        if len(rep) < 1:
            messagebox.showerror('Missing Path', 'Choose Path')
        else:
            path = rep

    # display the active log
    def display_log(self):
        global active_log
        log = ""
        for i in range(len(active_log)):
            tmp = active_log[i]
            log += tmp[0] + " " + tmp[1] + " " + str(tmp[2]) + "\n"
        messagebox.showinfo('Active Log', log)

    # closing the app
    def on_close(self):
        sys.exit(0)


def main():
    global path
    global screen
    global tree
    vt = VirusTotal()
    screen.title('O-Virus')
    screen.protocol("WM_DELETE_WINDOW", vt.on_close)
    builder = pg.Builder()
    builder.add_from_file('virtual_gui.ui')
    screen = builder.get_object('screen', screen)
    tree = builder.get_object('tree', screen)
    builder.connect_callbacks(vt)
    image = Image.open('icon.png')
    canvas = builder.get_object('symbol', screen)
    canvas.image = ImageTk.PhotoImage(image)
    canvas.create_image(0, 0, image=canvas.image, anchor='nw')
    screen.mainloop()
    return 0


if __name__ == "__main__":
    main()

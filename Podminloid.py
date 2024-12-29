import base64
from getpass import getpass
import os
from cryptography.fernet import Fernet
from cryptography.fernet import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import tkinter as tk
import tkinter.ttk as ttk
import sys
import pyperclip

# Arguments
if "--help" in sys.argv or "-h" in sys.argv:
    print("Podminloid is designed with security by obscurity in mind")
    print("It uses encryption to hide secrets")
    print("--help   Bring up this help menu")
    print("-h  Bring up this help menu")
    print("--terminal   Run in the terminal")
    exit()

using_terminal = False
if "--terminal" in sys.argv:
    using_terminal = True

del sys

# Setting save path
save_path = "./Resources/Chon/"
subDir = ""
noclear = False
if not os.path.exists("./Resources/Podminloid.configuration"):  # First run
    with open("./Resources/Podminloid.configuration", "w") as file:
        file.write("# GUI settings\n")
        file.write(f"theme=gruvbox-dark\n")
        file.write("# Terminal settings\n")
        file.write(f"noclear=False\n")
else:  # Open save preferences
    theme = "gruvbox-dark"
    with open("./Resources/Podminloid.configuration", "r") as file:
        for line in file:
            txt = line.strip()
            if txt.removeprefix("theme=") != txt:
                theme = txt.removeprefix("theme=")
            elif txt.removeprefix("noclear=") != txt:
                noclear = txt.removeprefix("noclear=") == "True"

fixed_salt = b"\x00" * 16
key = b"ZCf5sFgmzUyINw9KHbD3D7yfZeEhzG4rZ3uutOc2Yog=" # This key is generated with a blank password


# Useful functions


def generate_key_from_password(password):
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=fixed_salt,
        iterations=600000,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key


def encrypt_text(text):
    fernet = Fernet(key)
    return fernet.encrypt(text.encode("utf-8"))


def decrypt_text(text):
    fernet = Fernet(key)
    return fernet.decrypt(text)


def set_sub_dir(new):
    global subDir
    subDir = new


def create_password_file():
    string_output = encrypt_text("Verified!").decode("utf-8")
    with open(f"{save_path}.Podminion", "w") as file:
        file.write(string_output)


def return_decrypted_file_text(name):
    string_output = ""
    with open(f"{save_path}{subDir}{name}.cahenr", "r", encoding="utf-8") as file:
        for line in file:
            string_output += line.strip()
    return decrypt_text(string_output).decode("utf-8")


# User Interface


###
#   Structure of "items" input
#   [["title", "Words to print"],
#    ["sub_title", "Words to print"],
#    ["print", "Words to print"],
#    ["button", "Button Text", "unique_key", call_function, param, isstate("True", "False", "Refresh")],
#    ["button_text", "Button Text", "unique_key", call_function, param, "sidetext", isstate],
#    ["yn", "Input Prompt", "return_key"],
#    ["input", "Input Prompt", "return_key"],
#    ["secure_input", "Input Prompt", "return_key"]]
#
#   Structure of output
#   {"return_key": "return val"}
###
window = None
if not using_terminal:
    window = tk.Tk()
    window.config(bg="#282828")


class Renderer:
    def __init__(self, title):
        self.items = [["title", title]]
        self.input_text_length = 0
        self.tb_button_length = 0
        self.tb_text_length = 0

    def render(self):
        if using_terminal:
            return self.render_cli()
        else:
            return self.render_gui()

    def render_cli(self):
        ret_dict = {}
        if noclear == False:
            os.system("cls" if os.name == "nt" else "printf '\033c'")
        num_actions = 0
        buttons = {}
        for item in self.items:
            if item[0] == "title" or item[0] == "sub_title":
                print(f"\n~~~~~~~~~~ {item[1]} ~~~~~~~~~~\n")
            if item[0] == "print":
                print(item[1])
            if item[0] == "button_text":
                print(f"{item[2]}: {item[1]}, {item[5]}")
                buttons[item[2]] = (item[3], item[4])
                num_actions += 1
            if item[0] == "button":
                print(f"{item[2]}: {item[1]}")
                buttons[item[2]] = (item[3], item[4])
                num_actions += 1
            if item[0] == "input":
                return_val = input(item[1])
                return_key = item[2]
                ret_dict[return_key] = return_val
                num_actions += 1
            if item[0] == "secure_input":
                return_val = getpass(item[1])
                return_key = item[2]
                ret_dict[return_key] = return_val
                num_actions += 1
            if item[0] == "safe_secure_input":
                p1 = "placeholder"
                p2 = "placeholder2"
                while p1 != p2:
                    p1 = getpass(item[1])
                    p2 = getpass(item[1])
                    if p1 != p2:
                        print("Passwords do not match!")
                return_key = item[2]
                ret_dict[return_key] = p1
                num_actions += 1
            if item[0] == "yn":
                choice = "none"
                while choice.lower() not in ["y", "n"]:
                    choice = input("y/n: ")
                ret_dict[item[1]] = choice.lower() == "y"
                num_actions += 1
        if len(buttons) > 0:
            print()
            choice = None
            while choice not in buttons.keys():
                choice = input("Choice: ")
                if choice in buttons.keys():
                    func = buttons[choice][0]
                    if func == None:
                        return ret_dict
                    param = buttons[choice][1]
                    if param != None:
                        func(param)
                    else:
                        func()
                else:
                    print("Invalid input")
        if num_actions == 0:
            input("Continue? ")
        print()
        return ret_dict

    def create_function(self, func, param, frame, isstate):
        def cmd():
            if isstate == "True":
                global state, params
                state = func
                params = param

            if isstate in ["False", "Refresh"]:
                if param == None:
                    func()
                else:
                    func(param)
            if isstate in ["True", "Refresh"]:
                self.close_frame(frame)

        return cmd

    def close_frame(self, frame):
        if window != None:
            window.quit()
            window.unbind("<Return>")
        else:
            print("ERROR - WINDOW IS OF TYPE 'NONE")
        frame.destroy()

    def render_gui(self):
        global window
        if window == None:
            print("ERROR - WINDOW IS OF TYPE 'NONE'")
            return {}
        ret_dict = {}
        returning = {}

        render_space = tk.Frame(window, bg="#282828")

        num_actions = 0

        buttonbox = None
        buttonid = 0
        for item in self.items:
            if item[0] == "button":
                if buttonbox == None:
                    buttonbox = tk.Frame(render_space, bg="#282828")

                spacer = tk.Frame(buttonbox, bg="#282828", border=3)
                tk.Button(
                    spacer,
                    text=item[1],
                    command=self.create_function(
                        item[3], item[4], render_space, item[5]
                    ),
                    bg="#3c3836",
                    activebackground="#504945",
                    activeforeground="#fbf1c7",
                    fg="#EBDBB2",
                    font=("Ubuntu", 10, "normal"),
                ).pack()
                spacer.pack(side="right")

                buttonid += 1
                if buttonid == 4:
                    buttonbox.pack(side="top")
                    buttonbox = None
                    buttonid = 0

                num_actions += 1
            else:
                if not (buttonbox == None):
                    buttonbox.pack(side="top")
                    buttonbox = None
                    buttonid = 0

            if item[0] == "button_text":
                spacer = tk.Frame(render_space, bg="#282828", border=3)
                tk.Button(
                    spacer,
                    text=item[1],
                    command=self.create_function(
                        item[3], item[4], render_space, item[6]
                    ),
                    bg="#3c3836",
                    activebackground="#504945",
                    activeforeground="#fbf1c7",
                    fg="#EBDBB2",
                    font=("Ubuntu", 10, "normal"),
                    width=self.tb_button_length
                ).pack(side="left")
                tk.Label(
                    spacer,
                    text=item[5],
                    bg="#282828",
                    fg="#EBDBB2",
                    font=("Ubuntu", 10, "normal"),
                    width=self.tb_text_length,
                    anchor="w"
                ).pack(side="right")
                spacer.pack()
                num_actions += 1

            if item[0] == "title":
                tk.Label(render_space, height=1, bg="#282828").pack()
                ttk.Separator(render_space, orient="horizontal").pack(fill="x")
                tk.Label(
                    render_space,
                    text=item[1],
                    bg="#282828",
                    fg="#EBDBB2",
                    font=("Ubuntu", 20, "normal"),
                ).pack()
                ttk.Separator(render_space, orient="horizontal").pack(fill="x")
                tk.Label(render_space, height=1, bg="#282828").pack()
            if item[0] == "sub_title":
                tk.Label(render_space, height=1, bg="#282828").pack()
                ttk.Separator(render_space, orient="horizontal").pack(fill="x")
                tk.Label(
                    render_space,
                    text=item[1],
                    bg="#282828",
                    fg="#EBDBB2",
                    font=("Ubuntu", 15, "normal"),
                ).pack()
                ttk.Separator(render_space, orient="horizontal").pack(fill="x")
                tk.Label(render_space, height=1, bg="#282828").pack()
            if item[0] == "print":
                tk.Label(
                    render_space,
                    text=item[1],
                    bg="#282828",
                    fg="#EBDBB2",
                    font=("Ubuntu", 10, "normal"),
                ).pack()
            if item[0] == "input":
                frame = tk.Frame(render_space, bg="#1d2021", padx=1, pady=1, border=10, width=50+self.input_text_length)
                tk.Label(
                    frame,
                    text=item[1],
                    bg="#1d2021",
                    fg="#fbf1c7",
                    width=self.input_text_length,
                ).pack(side="left")
                return_val = tk.Entry(frame, bg="#3c3836", fg="#EBDBB2", width=50)
                return_val.pack(side="right")
                frame.pack()
                return_key = item[2]
                ret_dict[return_key] = return_val
                num_actions += 1
            if item[0] == "secure_input":
                frame = tk.Frame(render_space, bg="#1d2021", padx=1, pady=1, border=10, width=50+self.input_text_length)
                tk.Label(
                    frame,
                    text=item[1],
                    bg="#1d2021",
                    fg="#fbf1c7",
                    width=self.input_text_length,
                ).pack(side="left")
                return_val = tk.Entry(
                    frame, bg="#3c3836", fg="#EBDBB2", show="*", width=50
                )
                return_val.pack(side="right")
                return_val.focus()
                frame.pack()
                return_key = item[2]
                ret_dict[return_key] = return_val
                num_actions += 1
            if item[0] == "safe_secure_input":
                frame = tk.Frame(render_space, bg="#1d2021", padx=1, pady=1, border=10, width=50+self.input_text_length)
                tk.Label(
                    frame,
                    text=item[1],
                    bg="#1d2021",
                    fg="#fbf1c7",
                    width=self.input_text_length,
                ).pack(side="left")

                frame_right = tk.Frame(frame, bg="#1d2021")
                return_val = tk.Entry(
                    frame_right, bg="#3c3836", fg="#EBDBB2", show="*", width=50
                )
                return_val.pack(side="top")
                return_val_verify = tk.Entry(
                    frame_right, bg="#3c3836", fg="#EBDBB2", show="*", width=50
                )
                return_val_verify.pack(side="bottom")
                frame_right.pack(side="right")
                frame.pack()
                return_key = item[2]
                ret_dict[return_key] = return_val
                ret_dict[return_key + "_verify"] = return_val_verify
                num_actions += 1
            if item[0] == "yn":

                def choice_yn(choice):
                    returning[item[1]] = choice

                frame = tk.Frame(render_space, bg="#282828", padx=1, pady=1, border=10)
                tk.Button(
                    frame,
                    text="Yes",
                    command=self.create_function(
                        choice_yn, True, render_space, "Refresh"
                    ),
                    bg="#3c3836",
                    activebackground="#504945",
                    activeforeground="#fbf1c7",
                    fg="#EBDBB2",
                    font=("Ubuntu", 10, "normal"),
                ).pack(side="left")
                tk.Button(
                    frame,
                    text="No",
                    command=self.create_function(
                        choice_yn, False, render_space, "Refresh"
                    ),
                    bg="#3c3836",
                    activebackground="#504945",
                    activeforeground="#fbf1c7",
                    fg="#EBDBB2",
                    font=("Ubuntu", 10, "normal"),
                ).pack(side="right")
                frame.pack()
                num_actions += 1

        if not (buttonbox == None):
            buttonbox.pack(side="top")
            buttonbox = None

        if len(ret_dict) > 0:

            def submit(event=None):
                good = True
                for key, val in ret_dict.items():
                    verify = key.removesuffix("_verify")
                    if verify != key:
                        returning[key] = val.get()
                        if returning[verify] != returning[key]:
                            good = False
                    else:
                        returning[key] = val.get()
                if good:
                    self.close_frame(render_space)

            tk.Button(
                render_space,
                text="Submit",
                command=submit,
                bg="#3c3836",
                activebackground="#504945",
                activeforeground="#fbf1c7",
                fg="#EBDBB2",
                font=("Ubuntu", 10, "normal"),
            ).pack()
            window.bind("<Return>", submit)

        if num_actions == 0:

            def cmd(event=None):
                self.close_frame(render_space)

            tk.Button(
                render_space,
                text="Continue?",
                command=cmd,
                bg="#3c3836",
                activebackground="#504945",
                activeforeground="#fbf1c7",
                fg="#EBDBB2",
                font=("Ubuntu", 10, "normal"),
            ).pack()

            window.bind("<Return>", cmd)

        render_space.pack(fill="x")
        window.mainloop()

        return returning

    def print(self, text):
        self.items.append(["print", text])

    def title(self, text):
        self.items.append(["title", text])

    def sub_title(self, text):
        self.items.append(["sub_title", text])

    def input(self, prompt, key):
        self.items.append(["input", prompt, key])
        if self.input_text_length < len(prompt):
            self.input_text_length = len(prompt)

    def secure_input(self, prompt, key):
        self.items.append(["secure_input", prompt, key])
        if self.input_text_length < len(prompt):
            self.input_text_length = len(prompt)

    def safe_secure_input(self, prompt, key):
        self.items.append(["safe_secure_input", prompt, key])
        if self.input_text_length < len(prompt):
            self.input_text_length = len(prompt)

    def button(self, prompt, buttonid, function, params, isstate="True"):
        self.items.append(["button", prompt, buttonid, function, params, isstate])

    def button_text(self, prompt, buttonid, function, params, sidetext, isstate="True"):
        self.items.append(
            ["button_text", prompt, buttonid, function, params, sidetext, isstate]
        )
        if self.tb_text_length < len(sidetext):
            self.tb_text_length = len(sidetext)
        if self.tb_button_length < len(prompt):
            self.tb_button_length = len(prompt)

    def yn(self, key):
        self.items.append(["yn", key])


def main_window():
    global key
    renderer = Renderer("Main")
    if not os.path.exists(f"{save_path}.Podminion"):
        renderer.print("Your Master Password has not been set yet!")
        renderer.safe_secure_input("Master Password: ", "master_password")
    else:
        renderer.secure_input("Master Password: ", "master_password")
    master_password = renderer.render()["master_password"]

    key = generate_key_from_password(master_password)

    if not os.path.exists(save_path):  # Set password
        os.makedirs(save_path)
        create_password_file()
    if os.path.exists(f"{save_path}.Podminion"):  # Tests the password if it is valid
        try:
            string_output = ""
            with open(f"{save_path}.Podminion", "r", encoding="utf-8") as file:
                for line in file:
                    string_output += line.strip()
            decrypt_text(string_output).decode("utf-8")
        except:
            renderer = Renderer("Main")
            renderer.print("Incorrect Password!")
            renderer.render()
            return
    else:  # If the password file does not exist, it creates it
        open(f"{save_path}.Podminion", "x").close()
        create_password_file()
    global state, params
    state = show_all_passwords
    params = None


def show_all_passwords():
    renderer = Renderer("Show All")
    renderer.print(f"Current Sub Directory: /{subDir}")

    renderer.sub_title("Current Passwords")

    folder_content_names = os.listdir(save_path + subDir)
    buttons = 0
    for password_name in folder_content_names:
        short_name = password_name.removesuffix(".cahenr")
        if short_name != password_name:
            renderer.button(
                short_name, str(buttons), show_password_contents, short_name
            )
            buttons += 1

    folder_content_folders = next(os.walk(save_path + subDir))[1]
    if len(folder_content_folders) > 0:
        renderer.sub_title("Folders")
        for folder_name in folder_content_folders:
            renderer.button(
                folder_name,
                str(buttons),
                set_sub_dir,
                str(subDir + folder_name + "/"),
                "Refresh",
            )
            buttons += 1

    renderer.sub_title("Other")

    renderer.button("new", "n", create_new_password, None)
    if subDir != "":
        renderer.button("root", "r", set_sub_dir, "", "Refresh")
    renderer.button("quit", "q", quit_func, None)
    renderer.render()


def quit_func():
    exit()


def show_password_contents(name):
    renderer = Renderer(name)
    try:
        show_text = return_decrypted_file_text(name)
        text_lines = show_text.splitlines()
        button_num = 1
        for line in text_lines:
            show_text = line.strip()
            if show_text.removeprefix("<CP_U>") != show_text:
                usertext = show_text.removeprefix("<CP_U>")
                renderer.button_text(
                    "Username",
                    str(button_num),
                    pyperclip.copy,
                    usertext,
                    usertext,
                    "False",
                )
                button_num += 1
            elif show_text.removeprefix("<CP_P>") != show_text:
                passtext = show_text.removeprefix("<CP_P>")
                show_passtext = "*" * len(passtext)
                renderer.button_text(
                    "Password",
                    str(button_num),
                    pyperclip.copy,
                    passtext,
                    show_passtext,
                    "False",
                )
                button_num += 1
            elif show_text.removeprefix("#") == show_text:
                renderer.print(show_text)
    except:
        renderer.print("Decryption Failed!")
        renderer.print("\nDelete File?\n")
        renderer.yn("choice")
        choice = renderer.render()["choice"]
        if choice:
            edit_password_delete(name)
        global state, params
        state = show_all_passwords
        params = None
        return

    renderer.sub_title(name)
    renderer.button("Edit", "e", edit_password, name)
    renderer.button("Return", "r", show_all_passwords, None)

    renderer.render()


def password_editor(name):
    renderer = Renderer(f"Edit {name}")
    show_text = return_decrypted_file_text(name)
    text_lines = show_text.splitlines()
    line_num = 1
    for line in text_lines:
        show_text = line.strip()
        renderer.button_text(
                str(line_num), str(line_num), password_line_edit, {"filename": name, "linenum": line_num}, show_text, "True"
        )
        line_num += 1
    renderer.sub_title(name)
    renderer.button("Return", "r", edit_password, name)
    renderer.render()

def password_line_edit(filedict):
    name, line_num = filedict["filename"], filedict["linenum"]
    renderer = Renderer(f"Edit {name}")
    show_text = return_decrypted_file_text(name)
    text_lines = show_text.splitlines()
    line_test = 1
    for line in text_lines:
        show_text = line.strip()
        if line_test == line_num:
            renderer.sub_title(show_text)
            renderer.input(f"{line_num}: ", "line") 
        else:
            renderer.print(show_text)
        line_test += 1
    renderer.sub_title(name)
    renderer.button("Return", "r", edit_password, name)

    ret = renderer.render()
    if ret.get("line") == None:
        return
    edited_line = ret["line"]

    line_test = 1
    new_text = ""
    for line in text_lines:
        show_text = line.strip()
        if line_test == line_num:
            new_text += edited_line
        else:
            new_text += show_text
        new_text += "\n"
        line_test += 1

    os.remove(f"{save_path}{subDir}{name}.cahenr")
    with open(f"{save_path}{subDir}{name}.cahenr", "wb") as file:
        file.write(encrypt_text(new_text))

    global state, params
    state = password_editor
    params = name



def edit_password(name):
    renderer = Renderer(f"Edit {name}")
    renderer.button("Edit contents", "1", password_editor, name)
    renderer.button("Delete", "2", edit_password_delete, name)
    renderer.button("return", "3", show_all_passwords, None)
    renderer.render()


def edit_password_delete(name):
    renderer = Renderer(f"Delete {name}")
    renderer.print("\nAre you sure?\n")
    renderer.yn("choice")
    choice = renderer.render()["choice"]
    if choice == True:
        os.remove(f"{save_path}{subDir}{name}.cahenr")
    global state, params
    state = show_all_passwords
    params = None


def create_new_password():
    renderer = Renderer("Create New")
    renderer.input("Name: ", "name")
    name = renderer.render()["name"]
    if os.path.exists(f"{save_path}{subDir}{name}.cahenr"):
        renderer = Renderer(f"Create {name}")
        renderer.print("The file exists!")
        renderer.render()
        show_all_passwords()
        return

    global state, params
    state = create_file
    params = name


def create_file(name):
    renderer = Renderer(f"Create {name}")
    renderer.input("Username: ", "username")
    renderer.safe_secure_input("Password: ", "password")
    renderer.input("Notes: ", "notes")
    data_dict = renderer.render()

    file_contents = "# Don't forget to encrypt the file when you are done!\n"
    file_contents += "<CP_U>" + data_dict["username"] + "\n"
    file_contents += "<CP_P>" + data_dict["password"] + "\n" + "\n"
    file_contents += data_dict["notes"]

    with open(f"{save_path}{subDir}{name}.cahenr", "wb") as file:
        file.write(encrypt_text(file_contents))

    global state, params
    state = show_all_passwords
    params = None


state = main_window
params = None
running = True
while running:
    if params == None:
        state()
    else:
        state(params)

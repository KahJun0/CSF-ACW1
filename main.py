from tkinter import *
from tkinter import ttk, filedialog, messagebox

import os
import pathlib

import mp3_steg
import utility


def select_file(sv: StringVar):
    filename = filedialog.askopenfilename(
        title='Open a file',
        initialdir='/', )

    try:
        sv.set(filename)
    except:
        messagebox.showinfo('Error', message='Invalid file selection')


def check_free_bits(file: StringVar, mode: StringVar):
    """Function takes in the file name and mode both in StringVar
    format and returns number of available bit positions"""
    if mode.get() == 'MP3':
        bits = mp3_steg.get_available_bits(utility.read_file_into_hex_list(file.get()))
        messagebox.showinfo('Available storage at different settings',
                            f'If bit 0 is used only: {bits / 8} bytes\n'
                            f'If bit 0 and 1: {bits * 2 / 8} bytes\n'
                            f'if bit 0-2: {bits * 3 / 8} bytes\n'
                            f'if bit 0-3: {bits * 4 / 8} bytes\n'
                            f'if bit 0-4: {bits * 5 / 8} bytes\n'
                            f'if bit 0-5: {bits * 6 / 8} bytes\n'
                            f'if bit 0-6: {bits * 7 / 8} bytes\n')


def begin_encode(cover_file: StringVar, payload_file: StringVar, mode: StringVar, bits: IntVar):
    cover_file = cover_file.get()
    payload_file = payload_file.get()
    mode = mode.get()
    bits = bits.get()
    if mode == 'MP3':
        try:
            save_dir = filedialog.askdirectory(title='Enter directory to save encoded mp3 at',
                                               initialdir='/')
            mp3_steg.write_secret_to_file(save_dir, cover_file, payload_file, bits + 1)
            messagebox.showinfo('Success', f'Your payload has been encoded. Take note of the following information,'
                                           ' the receiver needs to know it in order for a successful decoding!\n'
                                           f'Bits used: {bits}\n'
                                           f'File size: {os.stat(payload_file).st_size}\n'
                                           f'File extension: {pathlib.Path(payload_file).suffix}')
        except Exception as e:
            messagebox.showerror('Error', f'An error has occurred.\n{e}')


def begin_decode(encoded_file: StringVar, bits_used: IntVar, size_file: IntVar, file_ext: StringVar):
    encoded_file = encoded_file.get()
    bits_used = bits_used.get()
    size_file = size_file.get()
    file_ext = file_ext.get()
    try:
        save_as = filedialog.asksaveasfilename(title='Enter name of file to save as',
                                               initialdir='\\')
        print(save_as)
        status = mp3_steg.get_secret_from_file(encoded_file, size_file, bits_used + 1, save_as + file_ext)
        messagebox.showinfo('Success', f'{status}')
    except Exception as e:
        messagebox.showerror('Error', f'An error has occurred.\n[e')


root = Tk()
root.title('CSF-AWC1')

# Tab Control
tabControl = ttk.Notebook(root)

# Tabs
encodeTab = ttk.Frame(tabControl)
decodeTab = ttk.Frame(tabControl)
tabControl.add(encodeTab, text='Encode')
tabControl.add(decodeTab, text='Decode')

# Encode variable declarations
selected_cover_file_stringvar = StringVar(encodeTab)
selected_payload_file_stringvar = StringVar(encodeTab)
function_selected = StringVar(encodeTab)
mode_selected = StringVar(encodeTab)
num_bits_encode = IntVar(encodeTab)

# Decode variable declarations
encoded_file_stringvar = StringVar(decodeTab)
num_bits_decode_intvar = IntVar(decodeTab)
size_of_file_intvar = IntVar(decodeTab)
file_extension_stringvar = StringVar(decodeTab)

# Frame creation
frame = ttk.Frame(root, padding=10)
frame.grid()

# Encode Labels
cover_file_selection_label = Label(encodeTab, text='Cover file selected: ')
cover_selected_file_label = Label(encodeTab, textvariable=selected_cover_file_stringvar)
payload_file_selection_label = Label(encodeTab, text='Payload file selected: ')
payload_selected_file_label = Label(encodeTab, textvariable=selected_payload_file_stringvar)
mode_selection = Label(encodeTab, text='Select mode: ')
num_bits_label = Label(encodeTab, text='Select bits to use (0-7): ')

# Decode Labels
encoded_file_selection_label = Label(decodeTab, text='Selected file to decode')
encoded_selected_file_label = Label(decodeTab, textvariable=encoded_file_stringvar)
num_bits_used_label = Label(decodeTab, text='Bit position(s) used:')
size_of_file_label = Label(decodeTab, text='Size of file:')
file_extension_label = Label(decodeTab, text='File extension:')

# Dropdowns
mode_selection_dropdown = OptionMenu(encodeTab, mode_selected, 'PNG', 'MP3')

# Encode Buttons
select_cover_file_button = Button(encodeTab, text='Choose cover file:',
                                  command=lambda: select_file(selected_cover_file_stringvar))
select_payload_file_button = Button(encodeTab, text='Choose payload file:',
                                    command=lambda: select_file(selected_payload_file_stringvar))
try_encode_function_button = Button(encodeTab, text='Begin!',
                                    command=lambda: begin_encode(selected_cover_file_stringvar,
                                                                 selected_payload_file_stringvar,
                                                                 mode_selected,
                                                                 num_bits_encode))
get_num_bits_button = Button(encodeTab, text='Get number of bits available',
                             command=lambda: check_free_bits(selected_cover_file_stringvar, mode_selected))

# Decode Buttons
select_encoded_file_button = Button(decodeTab, text='Choose encoded file:',
                                    command=lambda: select_file(encoded_file_stringvar))
try_decode_function_button = Button(decodeTab, text='Begin!',
                                    command=lambda: begin_decode(encoded_file_stringvar,
                                                                 num_bits_decode_intvar,
                                                                 size_of_file_intvar,
                                                                 file_extension_stringvar))

# Spinbox
num_bits_selection = Spinbox(encodeTab, from_=0, to=7, textvariable=num_bits_encode)

# Entry box
num_bits_used_entry = ttk.Entry(decodeTab, textvariable=num_bits_decode_intvar)
size_of_file_entry = ttk.Entry(decodeTab, textvariable=size_of_file_intvar)
file_extension_entry = ttk.Entry(decodeTab, textvariable=file_extension_stringvar)

# Grid alignment
tabControl.grid(row=0, column=0, sticky=W, pady=2, padx=2)

# encodeTab Grid
cover_file_selection_label.grid(row=0, column=0, sticky=W, pady=2, padx=2)
cover_selected_file_label.grid(row=0, column=1, sticky=W, pady=2, padx=2)
select_cover_file_button.grid(row=0, column=2, sticky=E, pady=2, padx=2)
payload_file_selection_label.grid(row=1, column=0, sticky=W, pady=2, padx=2)
payload_selected_file_label.grid(row=1, column=1, sticky=W, pady=2, padx=2)
select_payload_file_button.grid(row=1, column=2, sticky=E, pady=2, padx=2)
mode_selection.grid(row=2, column=0, sticky=W, pady=2, padx=2)
mode_selection_dropdown.grid(row=2, column=2, sticky=E, pady=2, padx=2)
num_bits_label.grid(row=3, column=0, sticky=E, pady=2, padx=2)
num_bits_selection.grid(row=3, column=2, sticky=E, pady=2, padx=2)
try_encode_function_button.grid(row=4, column=2, sticky=E, pady=2, padx=2)
get_num_bits_button.grid(row=5, column=2, sticky=E, pady=2, padx=2)

# decodeTab Grid
encoded_file_selection_label.grid(row=0, column=0, sticky=W, pady=2, padx=2)
encoded_selected_file_label.grid(row=0, column=1, sticky=W, pady=2, padx=2)
select_encoded_file_button.grid(row=0, column=2, sticky=E, pady=2, padx=2)
num_bits_used_label.grid(row=1, column=0, sticky=W, pady=2, padx=2)
num_bits_used_entry.grid(row=1, column=2, sticky=E, pady=2, padx=2)
size_of_file_label.grid(row=2, column=0, sticky=W, pady=2, padx=2)
size_of_file_entry.grid(row=2, column=2, sticky=E, pady=2, padx=2)
file_extension_label.grid(row=3, column=0, sticky=W, pady=2, padx=2)
file_extension_entry.grid(row=3, column=2, sticky=E, pady=2, padx=2)
try_decode_function_button.grid(row=4, column=2, sticky=E, pady=2, padx=2)

# Main loop
root.mainloop()

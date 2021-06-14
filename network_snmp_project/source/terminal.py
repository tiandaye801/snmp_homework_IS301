#!/usr/bin/env python
#-*- coding:utf-8 -*-

import os, sys
import time
from threading import Thread
try:
    from tkinter import *
except ImportError:  #Python 2.x
    PythonVersion = 2
    from Tkinter import *
    from tkFont import Font
    from ttk import *
    #Usage:showinfo/warning/error,askquestion/okcancel/yesno/retrycancel
    from tkMessageBox import *
    #Usage:f=tkFileDialog.askopenfilename(initialdir='E:/Python')
    #import tkFileDialog
    #import tkSimpleDialog
else:  #Python 3.x
    PythonVersion = 3
    from tkinter.font import Font
    from tkinter.ttk import *
    from tkinter.messagebox import *
    #import tkinter.filedialog as tkFileDialog
    #import tkinter.simpledialog as tkSimpleDialog    #askstring()

class Application_ui(Frame):
    #这个类仅实现界面生成功能，具体事件处理代码在子类Application中。
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.master.title('Snmp Octets')
        self.master.geometry('600x400')
        self.createWidgets()

    def createWidgets(self):
        self.top = self.winfo_toplevel()

        self.style = Style()

        self.style.configure('Command1.TButton',font=('microsoft yahei',9))
        self.Command1 = Button(self.top, text='开始/停止', command=self.Command1_Cmd, style='Command1.TButton')
        self.Command1.place(relx=0.065, rely=0.06, relwidth=0.250, relheight=0.120)

        self.style.configure('Command2.TButton',font=('microsoft yahei',9))
        self.Command2 = Button(self.top, text='设定刷新频率和ip地址', command=self.Command2_Cmd, style='Command2.TButton')
        self.Command2.place(relx=0.065, rely=0.25, relwidth=0.250, relheight=0.120)

        self.style.configure('Command2.TButton',font=('microsoft yahei',9))
        self.Command3 = Button(self.top, text='载入mib', command=self.Command3_Cmd, style='Command3.TButton')
        self.Command3.place(relx=0.065, rely=0.44, relwidth=0.250, relheight=0.120)

        self.Text1Font = Font(font=('microsoft yahei',9))
        self.Text1 = Text(self.top, font=self.Text1Font)
        self.Text1.place(relx=0.582, rely=0.12, relwidth=0.293, relheight=0.185)

        self.Text2Font = Font(font=('microsoft yahei',9))
        self.Text2 = Text(self.top, font=self.Text2Font)
        self.Text2.place(relx=0.582, rely=0.401, relwidth=0.293, relheight=0.185)

        self.Text3Font = Font(font=('microsoft yahei',9))
        self.Text3 = Text(self.top, font=self.Text3Font)
        self.Text3.place(relx=0.582, rely=0.682, relwidth=0.293, relheight=0.185)
       
        self.Text4Var = StringVar(value='在这里输入监控端ip地址')
        self.Text4 = Entry(self.top, text='Text4', textvariable=self.Text4Var, font=('宋体',9))
        self.Text4.place(relx=0.065, rely=0.700, relwidth=0.293, relheight=0.050)

        self.Text5Var = StringVar(value='在这里输入刷新延迟')
        self.Text5 = Entry(self.top, text='Text5', textvariable=self.Text5Var, font=('宋体',9))
        self.Text5.place(relx=0.065, rely=0.800, relwidth=0.293, relheight=0.050)

        self.style.configure('Label1.TLabel',anchor='w', font=('microsoft yahei',9))
        self.Label1 = Label(self.top, text='IP数据报', style='Label1.TLabel')
        self.Label1.place(relx=0.598, rely=0.06, relwidth=0.147, relheight=0.050)

        self.style.configure('Label2.TLabel',anchor='w', font=('microsoft yahei',9))
        self.Label2 = Label(self.top, text='TCP数据报', style='Label2.TLabel')
        self.Label2.place(relx=0.598, rely=0.340, relwidth=0.147, relheight=0.050)

        self.style.configure('Label3.TLabel',anchor='w', font=('microsoft yahei',9))
        self.Label3 = Label(self.top, text='UDP数据报', style='Label3.TLabel')
        self.Label3.place(relx=0.598, rely=0.620, relwidth=0.147, relheight=0.050)


class Application(Application_ui):
    #这个类实现具体的事件处理回调函数。界面生成代码在Application_ui中。
    def __init__(self, master=None):
        Application_ui.__init__(self, master)

    def Command1_Cmd(self, event=None):
        test1=Thread(target=self.ip_test1)
        test1.start()

    def Command2_Cmd(self, event=None):
        global host
        global delay
        host=self.Text4Var.get()
        delay=float(self.Text5Var.get())

    def Command3_Cmd(self, event=None):
        miblocation='C:\\usr\\share\\snmp\\mibs'
        mibintegration(miblocation)
        

    def ip_test1(self):

        global flag
        global delay
        if(flag==False):
            flag=True
        else:
            flag=False
        counter_matter=0

        ip_in_datagrams_speed=0
        ip_out_datagrams_speed=0
        tcp_in_datagrams_speed=0
        tcp_out_datagrams_speed=0
        udp_in_datagrams_speed=0
        udp_out_datagrams_speed=0

        while(flag):


           ip_in_result=float(snmpWalk(host,'IP-MIB::ipInDelivers.0')[0].split(' ')[3])
           ip_out_result=float(snmpWalk(host,'IP-MIB::ipOutRequests.0')[0].split(' ')[3])
           ip_in_datagrams=round(ip_in_result)
           ip_out_datagrams=round(ip_out_result)
           if(counter_matter>0):
               ip_in_datagrams_speed=round((ip_in_datagrams-ip_in_datagrams_storage)/delay,2)
               ip_out_datagrams_speed=round((ip_out_datagrams-ip_out_datagrams_storage)/delay,2)
           ip_in_datagrams_storage=ip_in_datagrams
           ip_out_datagrams_storage=ip_out_datagrams
           
         
           tcp_in_result=float(snmpWalk(host,'TCP-MIB::tcpInSegs.0')[0].split(' ')[3])
           tcp_out_result=float(snmpWalk(host,'TCP-MIB::tcpOutSegs.0')[0].split(' ')[3])
           tcp_in_datagrams=round(tcp_in_result)
           tcp_out_datagrams=round(tcp_out_result)
           if(counter_matter>0):
               tcp_in_datagrams_speed=round((tcp_in_datagrams-tcp_in_datagrams_storage)/delay,2)
               tcp_out_datagrams_speed=round((tcp_out_datagrams-tcp_out_datagrams_storage)/delay,2)
           tcp_in_datagrams_storage=tcp_in_datagrams
           tcp_out_datagrams_storage=tcp_out_datagrams


           udp_in_result=float(snmpWalk(host,'UDP-MIB::udpInDatagrams.0')[0].split(' ')[3])
           udp_out_result=float(snmpWalk(host,'UDP-MIB::udpOutDatagrams.0')[0].split(' ')[3])
           udp_in_datagrams=round(udp_in_result)
           udp_out_datagrams=round(udp_out_result)
           if(counter_matter>0):
               udp_in_datagrams_speed=round((udp_in_datagrams-udp_in_datagrams_storage)/delay,2)
               udp_out_datagrams_speed=round((udp_out_datagrams-udp_out_datagrams_storage)/delay,2)
           udp_in_datagrams_storage=udp_in_datagrams
           udp_out_datagrams_storage=udp_out_datagrams

           self.Text1.delete('0.0',END)
           self.Text2.delete('0.0',END)
           self.Text3.delete('0.0',END)

           self.Text1.insert('1.0',"IP总发送数据报:"+str(ip_out_datagrams)+"个"+'\n'+"IP总接收数据报:"+str(ip_in_datagrams)+'个'+'\n'+"IP发送数据报速度:"+str(ip_out_datagrams_speed)+'个/s'+'\n'+"IP接收数据报速度:"+str(ip_in_datagrams_speed)+'个/s'+'\n')
           self.Text2.insert('1.0',"TCP总发送数据报:"+str(tcp_out_datagrams)+"个"+'\n'+"TCP总接收数据报:"+str(tcp_in_datagrams)+'个'+'\n'+"TCP发送数据报速度:"+str(tcp_out_datagrams_speed)+'个/s'+'\n'+"TCP接收数据报速度:"+str(tcp_in_datagrams_speed)+'个/s'+'\n')
           self.Text3.insert('1.0',"UDP总发送数据报:"+str(udp_out_datagrams)+"个"+'\n'+"UDP总接收数据报:"+str(udp_in_datagrams)+'个'+'\n'+"UDP发送数据报速度:"+str(udp_out_datagrams_speed)+'个/s'+'\n'+"UDP接收数据报速度:"+str(udp_in_datagrams_speed)+'个/s'+'\n')


           counter_matter+=1
           time.sleep(delay)
    


def mibintegration(mibdirs):
    localdir=os.getcwd()
    os.popen('xcopy '+str(localdir)+'\\miblibrary '+str(mibdirs))
           
def snmpWalk(host, oid):
    result = os.popen('snmpwalk -v 2c -c public ' + str(host) + ' ' + oid).read().split('\n')[:-1]
    return result        
        
if __name__ == "__main__":

    delay=3
    host='localhost'
    flag=False
    top = Tk()
    Application(top).mainloop()
    try: top.destroy()
    except: pass

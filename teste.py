import asyncio
import websockets
import json
import threading
import socket
import random
import time
import os
from tkinter import *
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

class EvoFacialServer:
    def __init__(self, root):
        self.root = root
        self.root.title("Servidor Evo Facial - Controle de NSR")
        self.root.geometry("350x350")
        self.root.resizable(False, False)
        
        # Variáveis de estado
        self.connected_devices = {}
        self.server = None
        self.server_thread = None
        self.collector_thread = None
        self.port = 8080
        self.auto_save = BooleanVar(value=True)
        self.collection_interval = 30  # 5 minutos padrão
        self.running = False
        self.collected_logs = set()
        
        # Persistência de NSR
        self.nsr_file = "nsr_counters.json"
        self.saved_nsr = self.load_nsr_counters()
        
        # Interface
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=BOTH, expand=True)
        
        # Configura as abas
        self.setup_monitor_tab()
        self.setup_config_tab()
        self.setup_nsr_tab()
        self.setup_sync_tab()
        
        self.detect_local_ip()

    def setup_monitor_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Monitoramento")
        
        # Controles de conexão
        ttk.Label(frame, text="IP do Servidor:").grid(column=1, row=1, sticky=W, pady=5)
        self.ip_entry = ttk.Entry(frame, width=20)
        self.ip_entry.grid(column=2, row=1, sticky=W, pady=5)
        
        ttk.Label(frame, text="Porta do Servidor:").grid(column=1, row=2, sticky=W, pady=5)
        self.port_entry = ttk.Entry(frame, width=10)
        self.port_entry.grid(column=2, row=2, sticky=W, pady=5)
        self.port_entry.insert(0, "8080")
        
        # Botão de controle
        self.start_btn = ttk.Button(
            frame, 
            text="Iniciar Servidor", 
            command=self.toggle_server,
            width=15
        )
        self.start_btn.grid(column=1, row=3, columnspan=2, pady=10)
        
        # Lista de equipamentos
        ttk.Label(frame, text="Equipamentos Conectados:").grid(column=1, row=4, columnspan=2, pady=(10,0), sticky=W)
        
        self.devices_listbox = Listbox(frame, height=12, width=70)
        self.devices_listbox.grid(column=1, row=5, columnspan=2)
        
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.devices_listbox.yview)
        scrollbar.grid(column=3, row=5, sticky=(N,S))
        self.devices_listbox.configure(yscrollcommand=scrollbar.set)
        
        # Status
        self.status_var = StringVar()
        self.status_var.set("Servidor parado")
        ttk.Label(frame, textvariable=self.status_var).grid(column=1, row=6, columnspan=2, pady=10)

    def setup_config_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Configurações")
        
        ttk.Label(frame, text="Intervalo de coleta (segundos):").grid(column=1, row=1, sticky=W, pady=5)
        self.interval_entry = ttk.Entry(frame, width=10)
        self.interval_entry.grid(column=2, row=1, sticky=W, pady=5)
        self.interval_entry.insert(0, str(self.collection_interval))
        
        ttk.Button(
            frame,
            text="Salvar Configurações",
            command=self.save_config,
            width=20
        ).grid(column=1, row=2, columnspan=2, pady=10)
        
        self.config_status = StringVar()
        ttk.Label(frame, textvariable=self.config_status).grid(column=1, row=3, columnspan=2)

    def setup_nsr_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Contadores NSR")
        
        columns = ("sn", "nsr_counter")
        self.nsr_tree = ttk.Treeview(frame, columns=columns, show="headings", height=12)
        
        self.nsr_tree.heading("sn", text="Serial do Equipamento")
        self.nsr_tree.heading("nsr_counter", text="Último NSR")
        self.nsr_tree.column("sn", width=250)
        self.nsr_tree.column("nsr_counter", width=150, anchor="center")
        
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.nsr_tree.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.nsr_tree.configure(yscrollcommand=scrollbar.set)
        
        self.nsr_tree.pack(fill=BOTH, expand=True)
        
        ttk.Button(
            frame,
            text="Atualizar Contadores",
            command=self.update_nsr_display,
            width=20
        ).pack(pady=10)

    def setup_sync_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Sincronizar NSR")
        
        ttk.Label(frame, text="Sincronização de Contadores:").pack(pady=10)
        
        ttk.Button(
            frame,
            text="Enviar NSR para Todos",
            command=self.sync_all_nsr,
            width=25
        ).pack(pady=5)
        
        ttk.Button(
            frame,
            text="Receber NSR de Todos",
            command=self.request_all_nsr,
            width=25
        ).pack(pady=5)
        
        self.sync_status = StringVar()
        ttk.Label(frame, textvariable=self.sync_status, wraplength=400).pack(pady=10)

    def load_nsr_counters(self):
        try:
            if os.path.exists(self.nsr_file):
                with open(self.nsr_file, 'r') as f:
                    return json.load(f)
            return {}
        except:
            return {}

    def save_nsr_counters(self):
        try:
            with open(self.nsr_file, 'w') as f:
                json.dump(self.saved_nsr, f)
        except Exception as e:
            print(f"Erro ao salvar contadores: {e}")

    def get_nsr_counter(self, sn):
        return self.saved_nsr.get(sn, 1)

    def increment_nsr_counter(self, sn):
        self.saved_nsr[sn] = self.saved_nsr.get(sn, 1) + 1
        self.save_nsr_counters()
        return self.saved_nsr[sn]

    def toggle_server(self):
        if self.server is None:
            self.start_server()
        else:
            self.stop_server()

    def start_server(self):
        try:
            self.port = int(self.port_entry.get())
            ip = self.ip_entry.get()
            
            if not ip:
                messagebox.showerror("Erro", "Informe um IP válido!")
                return
            
            if self.port < 1024 or self.port > 65535:
                messagebox.showerror("Erro", "Porta inválida! Use um número entre 1024 e 65535.")
                return
            
            self.start_btn.config(text="Parar Servidor")
            self.status_var.set(f"Servidor rodando em {ip}:{self.port}")
            
            self.server_thread = threading.Thread(target=self.run_async_server, daemon=True)
            self.server_thread.start()
            
            self.running = True
            self.collector_thread = threading.Thread(target=self.run_collector, daemon=True)
            self.collector_thread.start()
            
        except ValueError:
            messagebox.showerror("Erro", "Porta inválida! Use um número entre 1024 e 65535.")

    def run_async_server(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        start_server = websockets.serve(
            self.handle_connection,
            self.ip_entry.get(),
            self.port,
            ping_interval=None
        )
        
        self.server = loop.run_until_complete(start_server)
        
        try:
            loop.run_forever()
        except:
            pass
        finally:
            loop.close()

    def stop_server(self):
        if self.server:
            self.server.close()
            self.server = None
        
        self.running = False
        self.start_btn.config(text="Iniciar Servidor")
        self.status_var.set("Servidor parado")
        self.connected_devices = {}
        self.update_devices_list()
        self.update_nsr_display()

    def run_collector(self):
        while self.running:
            now = datetime.now()
            today = now.strftime("%Y-%m-%d")
            
            for sn, device in list(self.connected_devices.items()):
                if 'websocket' in device and device['websocket'].open:
                    try:
                        asyncio.run(self.send_getnewlog(device['websocket']))
                        asyncio.run(self.send_getalllog(device['websocket'], today, today))
                    except Exception as e:
                        print(f"Erro ao solicitar logs para {sn}: {e}")
            
            time.sleep(self.collection_interval)

    async def send_getnewlog(self, websocket):
        try:
            command = {"cmd": "getnewlog", "stn": True}
            await websocket.send(json.dumps(command))
        except Exception as e:
            print(f"Erro ao enviar getnewlog: {e}")

    async def send_getalllog(self, websocket, start_date, end_date):
        try:
            command = {
                "cmd": "getalllog",
                "stn": True,
                "from": start_date,
                "to": end_date
            }
            await websocket.send(json.dumps(command))
        except Exception as e:
            print(f"Erro ao enviar getalllog: {e}")

    async def send_nsr_update(self, websocket, nsr_value):
        try:
            command = {
                "cmd": "setnsr",
                "nsr": nsr_value
            }
            await websocket.send(json.dumps(command))
        except Exception as e:
            print(f"Erro ao enviar NSR: {e}")

    async def request_nsr(self, websocket):
        try:
            command = {"cmd": "getnsr"}
            await websocket.send(json.dumps(command))
            response = await websocket.recv()
            data = json.loads(response)
            return data.get("nsr", 1)
        except Exception as e:
            print(f"Erro ao obter NSR: {e}")
            return 1

    def sync_all_nsr(self):
        if not self.connected_devices:
            messagebox.showwarning("Aviso", "Nenhum equipamento conectado!")
            return
            
        for sn, device in self.connected_devices.items():
            if 'websocket' in device and device['websocket'].open:
                try:
                    current_nsr = self.saved_nsr.get(sn, 1)
                    asyncio.run(self.send_nsr_update(device['websocket'], current_nsr))
                    self.sync_status.set(f"NSR enviado para {sn}: {current_nsr}")
                except Exception as e:
                    self.sync_status.set(f"Erro ao sincronizar {sn}: {str(e)}")

    def request_all_nsr(self):
        if not self.connected_devices:
            messagebox.showwarning("Aviso", "Nenhum equipamento conectado!")
            return
            
        for sn, device in self.connected_devices.items():
            if 'websocket' in device and device['websocket'].open:
                try:
                    nsr = asyncio.run(self.request_nsr(device['websocket']))
                    self.saved_nsr[sn] = nsr
                    if sn in self.connected_devices:
                        self.connected_devices[sn]["nsr_counter"] = nsr
                    self.sync_status.set(f"NSR recebido de {sn}: {nsr}")
                except Exception as e:
                    self.sync_status.set(f"Erro ao obter NSR de {sn}: {str(e)}")
        
        self.save_nsr_counters()
        self.update_nsr_display()

    def get_log_hash(self, record):
        return hash((
            record.get("enrollid"),
            record.get("time"),
            record.get("mode"),
            record.get("event")
        ))

    async def handle_connection(self, websocket, path):
        device_info = None
        
        try:
            message = await websocket.recv()
            data = json.loads(message)
            
            if data.get("cmd") == "reg":
                sn = data.get("sn", "Desconhecido")
                
                if sn not in self.connected_devices:
                    # Sincroniza NSR com equipamento
                    try:
                        device_nsr = await self.request_nsr(websocket)
                        current_nsr = max(device_nsr, self.get_nsr_counter(sn))
                    except:
                        current_nsr = self.get_nsr_counter(sn)
                    
                    self.connected_devices[sn] = {
                        "nsr_counter": current_nsr,
                        "websocket": websocket,
                        "ip": websocket.remote_address[0],
                        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "devinfo": data.get("devinfo", {})
                    }
                
                device_info = self.connected_devices[sn]
                device_info["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                self.update_devices_list()
                self.update_nsr_display()
                
                response = {
                    "ret": "reg",
                    "result": True,
                    "cloudtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                await websocket.send(json.dumps(response))
                
                while True:
                    try:
                        message = await websocket.recv()
                        data = json.loads(message)
                        device_info["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        self.update_devices_list()
                        
                        if data.get("ret") in ["getnewlog", "getalllog"] and data.get("result"):
                            new_records = [
                                record for record in data.get("record", []) 
                                if self.get_log_hash(record) not in self.collected_logs
                            ]
                            
                            if new_records:
                                self.collected_logs.update(self.get_log_hash(r) for r in new_records)
                                filtered_data = data.copy()
                                filtered_data["record"] = new_records
                                self.save_to_afd(sn, filtered_data)
                            
                            if data.get("count", 0) > len(data.get("record", [])):
                                response = {
                                    "ret": data["ret"],
                                    "result": True,
                                    "stn": False,
                                    "cloudtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                }
                                await websocket.send(json.dumps(response))
                        
                    except websockets.exceptions.ConnectionClosed:
                        break
        
        except Exception as e:
            print(f"Erro na conexão: {e}")
        finally:
            if device_info:
                sn = data.get("sn", "Desconhecido")
                if sn in self.connected_devices:
                    del self.connected_devices[sn]
                    self.update_devices_list()
                    self.update_nsr_display()

    def save_to_afd(self, sn, log_data):
        filename = f"AFD{sn}.txt"
        
        # Lê registros existentes
        existing_records = []
        try:
            with open(filename, "r", encoding='utf-8') as f:
                existing_records = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            pass
        
        # Processa novos registros
        new_records = []
        if "record" in log_data:
            for record in log_data["record"]:
                new_records.append(self.format_afd_record(record, sn))
                current_nsr = self.increment_nsr_counter(sn)
                self.connected_devices[sn]["nsr_counter"] = current_nsr
                
                # Sincroniza NSR com equipamento
                try:
                    asyncio.run(self.send_nsr_update(
                        self.connected_devices[sn]['websocket'],
                        current_nsr
                    ))
                except Exception as e:
                    print(f"Erro ao sincronizar NSR com {sn}: {e}")
        
        # Combina e ordena
        all_records = existing_records + new_records
        all_records.sort(key=lambda x: x.split('3')[1][:19])
        
        # Reescreve arquivo
        with open(filename, "w", encoding='utf-8') as f:
            f.write("\n".join(all_records) + "\n")
        
        self.update_nsr_display()

    def format_afd_record(self, record, sn):
        nsr = str(self.connected_devices[sn]["nsr_counter"]).zfill(9)
        
        time_str = record.get("time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        try:
            log_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        except:
            log_time = datetime.now()
        
        formatted_time = log_time.strftime("%Y-%m-%dT%H:%M:%S-0300")
        enrollid = str(record.get("enrollid", "0")).zfill(11)
        random_code = ''.join(random.choices('ABCDEF0123456789', k=4))
        
        return f"{nsr}3{formatted_time}{enrollid} {random_code}"

    def update_devices_list(self):
        self.devices_listbox.delete(0, END)
        for sn, device in self.connected_devices.items():
            self.devices_listbox.insert(END, f"{sn} - {device['ip']} - {device['last_seen']}")

    def update_nsr_display(self):
        for item in self.nsr_tree.get_children():
            self.nsr_tree.delete(item)
        for sn, device in self.connected_devices.items():
            self.nsr_tree.insert("", "end", values=(sn, device.get("nsr_counter", 1)))

    def detect_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            self.ip_entry.insert(0, local_ip)
        except:
            self.ip_entry.insert(0, "127.0.0.1")

    def save_config(self):
        try:
            new_interval = int(self.interval_entry.get())
            if new_interval < 30:
                messagebox.showwarning("Aviso", "O intervalo mínimo é 30 segundos!")
                return
            self.collection_interval = new_interval
            self.config_status.set(f"Configurações salvas! Intervalo: {new_interval}s")
        except ValueError:
            messagebox.showerror("Erro", "Digite um número válido para o intervalo!")

    def on_close(self):
        self.save_nsr_counters()
        self.root.destroy()

if __name__ == "__main__":
    root = Tk()
    app = EvoFacialServer(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
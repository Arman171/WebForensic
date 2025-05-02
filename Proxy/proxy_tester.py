import requests
import csv
import concurrent.futures
import time
import sys
import os
import matplotlib.pyplot as plt
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init()

# ASCII Art and Banner
BANNER = f"""
{Fore.CYAN}
  _____           _                        _____         _            
 |  __ \         | |                      |_   _|       | |           
 | |__) | __ ___ | |_ ___  _ __ _ __ ___    | | ___  ___| |_ ___ _ __ 
 |  ___/ '__/ _ \| __/ _ \| '__| '_ ` _ \   | |/ _ \/ __| __/ _ \ '__|
 | |   | | | (_) | || (_) | |  | | | | | | _| |  __/\__ \ ||  __/ |   
 |_|   |_|  \___/ \__\___/|_|  |_| |_| |_| \___/\___||___/\__\___|_|  
{Style.RESET_ALL}
"""

def create_results_dir():
    """Create directory for test results if it doesn't exist"""
    if not os.path.exists("proxy_results"):
        os.makedirs("proxy_results")
    return "proxy_results"

def save_chart(working_proxies, dir_path):
    """Save a bar chart of the fastest proxies"""
    if not working_proxies:
        return
    
    # Prepare data
    proxies = [f"Proxy {i+1}" for i in range(len(working_proxies))]
    speeds = [speed for _, speed in working_proxies]
    
    # Create chart
    plt.figure(figsize=(10, 6))
    bars = plt.bar(proxies, speeds, color='green')
    plt.xlabel('Proxies')
    plt.ylabel('Response Time (ms)')
    plt.title('Proxy Response Times')
    
    # Add value labels
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{height} ms',
                ha='center', va='bottom')
    
    # Save chart
    chart_path = os.path.join(dir_path, "proxy_speeds.png")
    plt.savefig(chart_path)
    plt.close()
    return chart_path

def animate_text(text):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.03)
    print()

def loading_animation():
    chars = "/—\\|"
    for _ in range(10):
        for char in chars:
            sys.stdout.write(f"\r{Fore.YELLOW}Testing proxies... {char}{Style.RESET_ALL}")
            sys.stdout.flush()
            time.sleep(0.1)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def test_proxy(proxy, test_url="http://www.google.com", timeout=5):
    proxies = {
        "http": f"http://{proxy}",
        "https": f"http://{proxy}"
    }
    
    try:
        start_time = time.time()
        response = requests.get(test_url, proxies=proxies, timeout=timeout)
        end_time = time.time()
        
        if response.status_code == 200:
            speed = round((end_time - start_time) * 1000, 2)  # in milliseconds
            return True, speed
    except Exception as e:
        return False, 0
    return False, 0

def single_proxy_test():
    clear_screen()
    print(BANNER)
    proxy = input(f"{Fore.GREEN}[+] Enter the proxy (format: ip:port or user:pass@ip:port): {Style.RESET_ALL}")
    
    print(f"\n{Fore.BLUE}[*] Testing proxy: {proxy}{Style.RESET_ALL}")
    loading_animation()
    
    success, speed = test_proxy(proxy)
    
    results_dir = create_results_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if success:
        print(f"\n{Fore.GREEN}[✓] Proxy is working! Response time: {speed} ms{Style.RESET_ALL}")
        
        # Save result
        with open(os.path.join(results_dir, f"working_proxy_{timestamp}.txt"), 'w') as f:
            f.write(f"Proxy: {proxy}\nResponse Time: {speed} ms\nStatus: Working\n")
    else:
        print(f"\n{Fore.RED}[✗] Proxy is not working{Style.RESET_ALL}")
        with open(os.path.join(results_dir, f"failed_proxy_{timestamp}.txt"), 'w') as f:
            f.write(f"Proxy: {proxy}\nStatus: Failed\n")

def csv_proxy_test():
    clear_screen()
    print(BANNER)
    file_path = input(f"{Fore.GREEN}[+] Enter the path to CSV file (format: ip,port or ip,port,user,pass): {Style.RESET_ALL}")
    
    working_proxies = []
    total_proxies = 0
    results_dir = create_results_dir()
    
    try:
        with open(file_path, 'r') as file:
            reader = csv.reader(file)
            proxies = []
            
            for row in reader:
                if len(row) >= 2:
                    if len(row) >= 4:
                        proxy = f"{row[2]}:{row[3]}@{row[0]}:{row[1]}"
                    else:
                        proxy = f"{row[0]}:{row[1]}"
                    proxies.append(proxy)
            
            total_proxies = len(proxies)
            print(f"\n{Fore.BLUE}[*] Found {total_proxies} proxies to test{Style.RESET_ALL}")
            
            if not proxies:
                print(f"{Fore.RED}[!] No valid proxies found in the file{Style.RESET_ALL}")
                return
            
            print(f"{Fore.YELLOW}[*] Testing proxies... (This may take a while){Style.RESET_ALL}")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                results = list(executor.map(test_proxy, proxies))
                
                for i, (success, speed) in enumerate(results):
                    if success:
                        working_proxies.append((proxies[i], speed))
                        sys.stdout.write(f"\r{Fore.GREEN}[✓] Working: {len(working_proxies)}/{total_proxies}{Style.RESET_ALL}")
                    else:
                        sys.stdout.write(f"\r{Fore.RED}[✗] Failed: {i+1-len(working_proxies)}/{total_proxies}{Style.RESET_ALL}")
                    sys.stdout.flush()
            
            print(f"\n\n{Fore.CYAN}[*] Test completed!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Working proxies: {len(working_proxies)}/{total_proxies}{Style.RESET_ALL}")
            
            if working_proxies:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(results_dir, f"working_proxies_{timestamp}.csv")
                
                with open(output_file, 'w', newline='') as out_file:
                    writer = csv.writer(out_file)
                    writer.writerow(["Proxy", "Response Time (ms)"])
                    for proxy, speed in working_proxies:
                        writer.writerow([proxy, speed])
                
                # Save chart
                chart_path = save_chart(working_proxies[:10], results_dir)  # Show top 10 max
                if chart_path:
                    print(f"{Fore.BLUE}[*] Speed chart saved to: {chart_path}{Style.RESET_ALL}")
                
                print(f"\n{Fore.YELLOW}Top 5 fastest proxies:{Style.RESET_ALL}")
                working_proxies.sort(key=lambda x: x[1])
                for i, (proxy, speed) in enumerate(working_proxies[:5]):
                    print(f"{i+1}. {proxy} - {speed} ms")
    
    except FileNotFoundError:
        print(f"{Fore.RED}[!] File not found. Please check the path.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] An error occurred: {str(e)}{Style.RESET_ALL}")

def main():
    clear_screen()
    print(BANNER)
    animate_text(f"{Fore.YELLOW}Welcome to Proxy Tester Professional Tool{Style.RESET_ALL}")
    
    while True:
        print(f"\n{Fore.CYAN}Menu:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}1. Test a single proxy{Style.RESET_ALL}")
        print(f"{Fore.GREEN}2. Test proxies from CSV file{Style.RESET_ALL}")
        print(f"{Fore.RED}3. Exit{Style.RESET_ALL}")
        
        choice = input(f"\n{Fore.BLUE}[?] Select an option (1-3): {Style.RESET_ALL}")
        
        if choice == "1":
            single_proxy_test()
        elif choice == "2":
            csv_proxy_test()
        elif choice == "3":
            print(f"\n{Fore.YELLOW}[*] Thank you for using Proxy Tester!{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}[!] Invalid choice. Please try again.{Style.RESET_ALL}")
        
        input(f"\n{Fore.BLUE}[*] Press Enter to continue...{Style.RESET_ALL}")
        clear_screen()
        print(BANNER)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Program interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
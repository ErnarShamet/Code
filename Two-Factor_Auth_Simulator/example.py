import pyotp
import time
import qrcode
import base64
from io import BytesIO

# --- 1. Настройка: Секретный ключ (должен храниться безопасно!) ---
# Используйте pyotp.random_base32() для генерации нового, совместимого с Google Authenticator ключа
SECRET_KEY = pyotp.random_base32() 

# --- 2. Инициализация TOTP и HOTP объектов ---
# TOTP (Time-Based) - код меняется каждые 30 секунд (по умолчанию)
totp = pyotp.TOTP(SECRET_KEY) 
# HOTP (Counter-Based) - код меняется при каждом увеличении счетчика
hotp = pyotp.HOTP(SECRET_KEY)

# --- 3. Генерация Provisioning URI и QR-кода (для совместимости с внешними приложениями) ---
# Этот URI содержит секретный ключ и настройки
uri = totp.provisioning_uri(
    name='Simulator@Example.com',
    issuer_name='2FA Simulator (TOTP)'
)

# Функция для генерации QR-кода (опционально, требует 'qrcode')
def generate_qr_code_base64(uri_data):
    """Генерирует QR-код из URI и возвращает его в формате Base64."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri_data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Сохраняем изображение в буфер памяти и кодируем в Base64
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return img_str


# --- 4. Демонстрация TOTP (временной) ---
print("--- СИМУЛЯТОР TOTP (Time-Based) ---")
print(f"Секретный ключ (для сервера): {SECRET_KEY}")
print(f"URI для Provisioning: {uri}\n")

# Демонстрация изменения кода во времени
for i in range(3): # Показываем 3 интервала по 30 секунд
    current_otp = totp.now() # Генерация текущего кода
    print(f"Текущее время: {time.strftime('%H:%M:%S', time.gmtime())}")
    print(f"-> Сгенерированный OTP: {current_otp}")
    
    # Имитация проверки: код должен быть действителен
    is_valid_current = totp.verify(current_otp)
    print(f"   Проверка OTP ({current_otp}): {is_valid_current}")
    
    # Имитация "взлома" (ввод кода из предыдущего интервала)
    if i > 0:
        is_valid_old = totp.verify(last_otp)
        print(f"   Проверка СТАРОГО OTP ({last_otp}): {is_valid_old} (Должно быть False или True в окне толерантности)")
        
    last_otp = current_otp # Сохраняем для следующего цикла
    
    if i < 2:
        print("\nОжидание 30 секунд для смены кода (интервал TOTP)...")
        # В реальной жизни нужно дождаться следующего интервала (30 сек)
        # Для демонстрации подождем меньше, чтобы показать изменение
        time.sleep(3) # Ждем 3 секунды для быстрой демонстрации
        print("...")

print("\n--- Проверка Безопасности TOTP ---")
# TOTP устойчив к атакам повторного использования, так как код быстро меняется
# и имеет небольшое окно толерантности (ошибки времени).
# Основная уязвимость: утечка Секретного Ключа на сервере.
# Также можно проверить окно толерантности: totp.verify(otp, tolerance=1)

# --- 5. Демонстрация HOTP (по счетчику) ---
print("\n--- СИМУЛЯТОР HOTP (Counter-Based) ---")

# HOTP требует, чтобы сервер и клиент (приложение) синхронизировали счетчик
current_counter = 100 

for i in range(3):
    current_otp = hotp.at(current_counter) # Генерация кода для текущего счетчика
    print(f"Счетчик: {current_counter}")
    print(f"-> Сгенерированный OTP: {current_otp}")
    
    # Имитация проверки: код должен быть действителен с текущим счетчиком
    is_valid_current = hotp.verify(current_otp, current_counter)
    print(f"   Проверка OTP ({current_otp}, счетчик {current_counter}): {is_valid_current}")
    
    # После успешной проверки счетчик на стороне сервера должен увеличиться
    current_counter += 1
    
    # Имитация повторной попытки с тем же кодом (атака повторного использования)
    is_valid_old = hotp.verify(current_otp, current_counter - 1) # Проверка с уже использованным счетчиком
    print(f"   Повторная проверка ({current_otp}, старый счетчик {current_counter - 1}): {is_valid_old}") # Должно быть False после увеличения счетчика
    print("...")

print("\n--- Проверка Безопасности HOTP ---")
# HOTP уязвим к атакам "брутфорс" или атакам повторного использования, 
# если сервер не отслеживает увеличение счетчика. Если злоумышленник перехватит
# код и попробует его использовать, сервер должен проверить его и увеличить счетчик, 
# сделав код недействительным для будущего использования.

# --- 6. Информация о QR-коде для визуализации (требует 'qrcode') ---
try:
    qr_base64 = generate_qr_code_base64(uri)
    print("\n--- Визуальный интерфейс (QR-код) ---")
    print("Отсканируйте этот QR-код (Base64) с помощью Google Authenticator или Authy:")
    # В реальном интерфейсе здесь будет отображаться изображение QR-кода
    print("Для веб-интерфейса используйте: <img src='data:image/png;base64, ...' />")
    print(f"") # Тег для изображения
except ImportError:
    print("\nДля генерации QR-кода установите библиотеку 'qrcode' (pip install qrcode).")
    
# --- 7. Защита и проверка безопасности
print("\n--- Меры Безопасности ---")
print("1. **Конфиденциальность Секретного Ключа:** Ключ должен храниться на сервере в зашифрованном виде.")
print("2. **Окно Толерантности (TOTP):** Сервер должен допускать небольшие расхождения во времени (обычно +/- 1 интервал) для компенсации рассинхронизации часов.")
print("3. **Защита от Брутфорса:** Ограничение количества попыток ввода OTP для предотвращения подбора.")
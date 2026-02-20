@echo off
title Gamma Messenger
color 0A

echo ╔════════════════════════════════════╗
echo ║    Gamma Messenger для Windows     ║
echo ╚════════════════════════════════════╝
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo Python не установлен!
    echo Скачайте Python с: https://www.python.org/downloads/
    pause
    exit /b
)

echo Python найден

git clone https://github.com/Iaroslav-Palekhov/gamma-messenger.git

cd gamma-messenger/


if not exist "venv" (
    echo Создание виртуального окружения...
    python -m venv venv
)

echo Активация виртуального окружения...
call venv\Scripts\activate

echo Установка зависимостей...
pip install -r requirements.txt


echo.
echo Готово!
echo.
echo Запуск Gamma Messenger...
echo Сервер запущен на: http://localhost:2200
echo Для остановки нажмите Ctrl+C
echo.

:: Запуск приложения
py app.py

pause

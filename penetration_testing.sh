#!/bin/bash

function show_pen_test_menu {
    echo "=================================================="
    echo "          Menú de Pruebas de Penetración          "
    echo "=================================================="
    echo "1. Escaneo de Puertos"
    echo "2. Fuerza Bruta SSH"
    echo "3. Enumeración de Red"
    echo "4. Enumeración DNS"
    echo "5. Salir"
    
    read -p "Elija una opción: " choice
    
    case $choice in
        1) start_port_scanning ;;
        2) start_ssh_brute_force ;;
        3) start_network_enumeration ;;
        4) start_dns_enumeration ;;
        5) exit 0 ;;
        *) 
            echo "Opción inválida, por favor ingrese alguna opción que se encuentre en el menú."
            show_pen_test_menu 
            ;;
    esac
}

function start_port_scanning {
    read -p "Introduce la IP a escanear: " target_ip
    read -p "Introduce el puerto de inicio: " start_port
    read -p "Introduce el puerto final: " end_port

    start_port=${start_port:-1}
    end_port=${end_port:-65535}

    echo "Iniciando escaneo de puertos en $target_ip desde el puerto $start_port hasta el puerto $end_port..."
    
    found_open_ports=false

    for port in $(seq $start_port $end_port); do
        timeout 1 bash -c "</dev/tcp/$target_ip/$port" &>/dev/null && {
            echo "El puerto $port está abierto."
            found_open_ports=true
        }
    done

    if [ "$found_open_ports" = false ]; then
        echo "No se encontraron puertos abiertos en el rango especificado."
    fi

    echo ""  # Add a space before returning to the menu
    show_pen_test_menu
}

function start_ssh_brute_force {
    read -p "Introduce la IP del servidor SSH: " target_ip

    user_list=("admin" "root" "usuario")
    password_list=("123456" "password" "admin123")

    echo "Iniciando ataque de fuerza bruta contra $target_ip..."
    for user in "${user_list[@]}"; do
        for password in "${password_list[@]}"; do
            echo "Probando credenciales: Usuario: $user, Contraseña: $password"
        done
    done

    echo "Ataque de fuerza bruta finalizado. No se encontraron credenciales válidas (simulado)."
    echo ""  # Add a space before showing the submenu
    show_submenu
}

function show_submenu {
    echo "-----------------------------------------"
    echo "          Acciones adicionales           "
    echo "-----------------------------------------"
    echo "1. Generar un reporte"
    echo "2. Volver a introducir datos para fuerza bruta SSH"
    echo "3. Realizar un respaldo de seguridad"
    echo "4. Regresar al menú principal"
    
    read -p "Elija una opción: " submenu_choice
    
    case $submenu_choice in
        1) generate_report ;;
        2) start_ssh_brute_force ;;  # Call the SSH brute force function again
        3) backup_security ;;
        4) show_pen_test_menu ;;
        *) 
            echo "Opción inválida. Intente de nuevo."
            show_submenu 
            ;;
    esac
}

function generate_report {
    report_file="ssh_brute_force_report_$(date +%Y%m%d_%H%M%S).txt"
    echo "Generando reporte del ataque de fuerza bruta SSH..."
    echo "Credenciales probadas durante el ataque de fuerza bruta:" > "$report_file"
    for user in "${user_list[@]}"; do
        for password in "${password_list[@]}"; do
            echo "Usuario: $user, Contraseña: $password" >> "$report_file"
        done
    done
    echo "Reporte guardado en: $report_file"
    echo ""  # Add a space before returning to the submenu
    show_submenu
}

function backup_security {
    backup_dir="backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    cp /etc/passwd "$backup_dir"
    cp /etc/group "$backup_dir"
    echo "Respaldo de seguridad realizado en el directorio: $backup_dir"
    echo ""  # Add a space before returning to the submenu
    show_submenu
}

function start_network_enumeration {
    echo "Enumerando dispositivos en la red local..."
    arp -a
    echo ""  # Add a space before returning to the menu
    show_pen_test_menu
}

function start_dns_enumeration {
    read -p "Introduce el dominio para la enumeración DNS: " domain
    
    echo "Consultando registros DNS para $domain..."
    echo "Registros A:"
    dig +short A $domain

    echo -e "\nRegistros MX:"
    dig +short MX $domain

    echo -e "\nRegistros CNAME:"
    dig +short CNAME $domain
    
    echo ""  # Add a space before returning to the menu
    show_pen_test_menu
}

# Start main menu
show_pen_test_menu

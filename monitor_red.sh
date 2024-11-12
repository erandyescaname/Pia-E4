#!/bin/bash

#preparation and presentation :)
echo "Monitoreo de red"
echo "El script requiere permisos sudo"
sudo mkdir -p /var/log/network_monitor
sudo chmod 777 /var/log/network_monitor


#iftop instalation
if ! dpkg -l | grep -q iftop; then
    echo "Instalando iftop..."
    if ! sudo apt update; then
        echo "Error al actualizar la lista de paquetes."
        exit 1
    fi

    if ! sudo apt install -y iftop; then
        echo "Error al instalar iftop."
        exit 1
    fi
else
    echo "iftop ya está instalado."
fi

# Initial variables
LOG_DIR="/var/log/network_monitor"
INTERFACE="eth0"  # this can be changed on option 6 of the menu
DURATION=60 #this can also be canged

#Variable verification
#Interface
validate_interface(){
        if ! ip link show "$1" &> /dev/null; then
                echo "Error: La interfaz '$1' no existe. Intente de nuevo."
                return 1
                break
        fi
        return 0
}
#Duration
validate_duration(){
        if ! [[ "$1" =~ ^[0-9]+$ ]] || [ "$1" -le 0 ]; then
                echo "Error: La duración debe ser un número positivo."
                return 1
        fi
        return 0
}
return 0

#function of cybersecurity tasks
security_task(){
	#red traffic
	echo "Capturando tráfico de red en la interfaz $INTERFACE durante $DURATION segundos>"
	sudo tcpdump -i $INTERFACE -w "$LOG_DIR/tcpdump_capture_$(date +'%Y%m%d_%H%M%S').pcap" &
        TCPDUMP_PID=$!
        sleep $DURATION
        sudo kill -9 $TCPDUMP_PID
        echo "Captura completada. Archivo guardado en $LOG_DIR" | tee -a $REPORT_FILE
        
	#active conections
        echo "Conexiones activas en $INTERFACE:"| tee -a $REPORT_FILE
        netstat -tulnp| tee -a $REPORT_FILE
        echo ""| tee -a $REPORT_FILE
	
	#monitos bandwith
        echo "Monitoreando el ancho de banda en la interfaz $INTERFACE durante $DURATION segundos..."| tee -a $REPORT_FILE
        sudo iftop -i $INTERFACE -t -s $DURATION| tee -a $REPORT_FILE

	#routing table
        echo "Tabla de enrutamiento:"| tee -a $REPORT_FILE
        netstat -r| tee -a $REPORT_FILE
        echo ""| tee -a $REPORT_FILE
}

echo "El proceso se ejecuta primero con los valores pre-establecidos de interfaz:eth0 y duracion:60"
security_task

#extra options menu
PS3='Elije la opcion: '
options=("Reporte de actividad" "Configurar interfaz y duracion (cambio de datos)" "Copia de seguridad" "Salir")  
select opt in "${options[@]}"
do
        case $opt in
		"Reporte de actividad")
			echo "Generando un nuevo reporte de actividad..." |  $REPORT_FILE
            		security_task
            		echo "Nuevo reporte generado: $REPORT_FILE"
            		;;
		"Configurar interfaz y duracion (cambio de datos)")
			while true; do
                                echo -n "Ingrese la interfaz de red a monitorear (actual: $INTERFACE): "
                                read new_interface
                                if [ -n "$new_interface" ]; then
                                        if validate_interface "$new_interface"; then
                                                INTERFACE="$new_interface"
                                                break
                                        else 'La interfaz '$new_interface' no existe'
                                        fi
                                else
                                        break
                                fi
                        done
                        while true; do
                                echo -n "Ingrese la duración de la captura en segundos (actual: $DURATION): "
                                read new_duration
                                if [ -n "$new_duration" ]; then
                                        if validate_duration "$new_duration"; then
                                                DURATION="$new_duration"
                                                break
                                        else 'La duracion '$new_duration' es invalida'
					fi
                                else
                                        break
                                fi
                        done
			security_task $new_interface $new_duration
                        ;;

		"Copia de seguridad")
			BACKUP_FILE="$LOG_DIR/security_backup_$(date +'%Y%m%d_%H%M%S').tar.gz"
            		echo "Generando copia de seguridad de los logs en $BACKUP_FILE"
            		tar -czf $BACKUP_FILE $LOG_DIR
            		echo "Copia de seguridad completada: $BACKUP_FILE"
            		;;

		"Salir")
			echo "Saliendo..."
			break
            		;;

        	*) echo "Opción inválida"
			;;
	esac
done

To auto-create new service user for monitoring of specific user, execute the script "admin_script.ps1" with the following parameters: service username, service password, monitored username, ip address of MALLEVEL server, port of MALLEVEL server, API Key for current endpoint.
.\admin_script.ps1 -service_user_name <service username> -service_user_password <service password> -monitored_user_name <monitored username> -ip_address <ip address> -port <port> -api_key <api key>
e.g.
.\admin_script.ps1 -monitored_user_name "test_user" -ip_address "172.22.50.93" -port "5000" -api_key "67fff093-5311-4ce1-8f10-43f54e1748f1"

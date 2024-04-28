import smtplib
import whois
import datetime
import socket

def check_smtp_connection123(mx_record):
    exchange = mx_record['exchange']
    address = mx_record['address']

    result = ()
    try:
        # Create an SMTP connection
        server = smtplib.SMTP(host=exchange, port=25, timeout=10)
        greeting = server.ehlo()  # Send an EHLO to the server
        if greeting[0] >= 200 and greeting[0] <= 299:
            result = (f"Successful SMTP connection to {exchange} at {address}", True)
        else:
            result = (f"Connection to {exchange} at {address} returned code {greeting[0]}", False)
        server.quit()
        return result
    except (socket.gaierror, socket.error) as e:
        return(f"Failed to connect to {exchange} at {address}. Error: {str(e)}", False)
    except smtplib.SMTPException as e:
        return(f"Failed, error occurred when connecting to {exchange} at {address}: {str(e)}", False)
    

def check_smtp_connection(mx_record):
    exchange = mx_record['exchange']
    address = mx_record['address']
    ports = [25, 587, 465]  # SMTP ports to check

    # Track the connection success on any of the ports
    connection_successful = False
    error_messages = [f"Failed to connect to {exchange} at {address} on ports:"]

    for port in ports:
        try:
            server = smtplib.SMTP(host=exchange, port=port, timeout=10)
            greeting = server.ehlo()  # Send an EHLO to the server
            if greeting[0] >= 200 and greeting[0] <= 299:
                connection_successful = True
                server.quit()
                break  # If connection is successful on any port, break out of the loop
            else:
                error_messages.append(f"Connection to {exchange} at {address} on port {port} returned code {greeting[0]}")
            server.quit()
        except (socket.gaierror, socket.error) as e:
            error_messages.append(f"{port}. Error: {str(e)}")
        except smtplib.SMTPException as e:
            error_messages.append(f"{port}: Error: {str(e)}")

    if not connection_successful:
        return (" ".join(error_messages), False)
    return (f"Successful SMTP connection to {exchange} at {address}", True)


def check_if_expired(mx_record):
    mx_domain = str(mx_record['exchange'])
    mx_domain = mx_domain.split('.')[-2] + '.' + mx_domain.split('.')[-1]

    try:
        mx_whois = whois.whois(mx_domain)
        if isinstance(mx_whois.expiration_date, list):
            expiration_date = mx_whois.expiration_date[0]
        else:
            expiration_date = mx_whois.expiration_date

        if expiration_date and expiration_date < datetime.datetime.now():
            #print(f"MX domain {mx_domain} is expired")
            return True
        else:
            #print(f"MX domain {mx_domain} has not expired")
            return False
    except whois.parser.PywhoisError:
        #print(f"WHOIS data not found for MX domain {mx_domain}")
        return None
    
    
def mx_check(mx_records):
    vulnerability = {}
    vulnerability_reason = []

    for mx_record in mx_records:
        connect_result = check_smtp_connection(mx_record)

        if not connect_result[1]:
            vulnerability_reason.append(connect_result[0])


        # Check for expired domain for current NS record
        expired = check_if_expired(mx_record)
        if expired == True:
            vulnerability_reason.append('MX record expired')
        elif expired == None:
            vulnerability_reason.append('WHOIS data not found')
        

        if vulnerability_reason:
            vulnerability[mx_record['exchange']] = vulnerability_reason
    
    return vulnerability
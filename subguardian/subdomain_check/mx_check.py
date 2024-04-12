import smtplib
import ssl

def check_mx_connect(mx_record):
    # Attempt to connect to the SMTP server
    smtp_server = str(mx_record['exchange'])
    ip = str(mx_record['address'])
    port = 25
    try:
        # Create an SMTP object
        server = smtplib.SMTP(smtp_server, port)
        # Setting debug level to 1 to print out the transaction with the server
        # server.set_debuglevel(1)  

        # Send an EHLO command to the SMTP server to establish the connection and identify the client to the server.
        server.ehlo()

        # If the server supports TLS
        if server.has_extn('STARTTLS'):
            # try secure connection
            print("TLS is supported.")
            server.starttls(context=ssl.create_default_context())
        else:
            print("TLS might not be supported")
            return "TSL"

        # Close the connection
        server.quit()
        
        print(f"Connection to {smtp_server} with ip {ip} on port {port} was successful.")
    except Exception as e:
        print(f"Error connecting to {smtp_server} with ip {ip} on port {port}: {e}")


def mx_check(mx_records):
    vulnerability = {}
    for mx_record in mx_records:
        connect_result = check_mx_connect(mx_record)
        if connect_result == "TSL":
            vulnerability[mx_record['exchange']] = "Might Lack of support for STARTTLS encryption."
            
    return
import smtplib


def sendmail(to_address, message):
    mail_user = "verify.ecom19@gmail.com"
    mail_password = "eqjo ugfi trnc ahuv"

    sent_from = mail_user
    to = [to_address, 'g.ganeshlex@gmail.com']
    subject = "Activation & Authorize Key"
    body = message

    email_text = """\
From: %s
To: %s
Subject: %s

%s
""" % (sent_from, ", ".join(to), subject, body)

    try:
        smtp_server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        smtp_server.ehlo()
        smtp_server.login(mail_user, mail_password)
        smtp_server.sendmail(sent_from, to, email_text)
        smtp_server.close()
        return "Email Sent Successfully!"
    except Exception as ex:
        return "Something went wrong…." + str(ex)
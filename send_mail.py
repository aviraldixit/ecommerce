from app import app
from flask import render_template
from flask_mail import Mail, Message

mail = Mail(app)


def send_contact_email(name, email, message):

    # user_email = email
    user_email = 'wihapi2659@hmnmw.com'
    subject = f'{name} tried reaching us'
    recipient_list = [user_email]
    detail_header = "{:<10} {:<10}".format('NAME:', name)
    detail_value = "{:<10} {:<10}".format('EMAIL:', email)
    message = message + '\n' + detail_header + '\n' + detail_value
    message_body = message
    msg = Message(subject, body=message_body, recipients=recipient_list)
    mail.send(msg)


def send_registration_email(user):
    request_url = app.config['REQUEST_URL']
    # user_email = user.email
    print(request_url)
    user_email = 'wihapi2659@hmnmw.com'
    subject = 'Welcome from FreshAlmonds'
    recipient_list = []
    recipient_list.append(user_email)
    msg = Message(subject, recipients=recipient_list)
    msg.html = render_template('email/new_user.html', user=user, url=request_url)
    mail.send(msg)


def send_pay_confirmation_email(name, order, email):
    request_url = app.config['REQUEST_URL']
    # user_email = email
    print(request_url)
    user_email = 'wihapi2659@hmnmw.com'
    subject = 'Order Confirmed from FreshAlmonds'
    recipient_list = []
    recipient_list.append(user_email)
    msg = Message(subject, recipients=recipient_list)
    msg.html = render_template('email/order-confirmation.html', name=name, order=order)
    mail.send(msg)

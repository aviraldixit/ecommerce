from app import db, login_manager
from flask_login import UserMixin
from collections import OrderedDict
from datetime import datetime


class User(db.Model, UserMixin):
    ROLE = OrderedDict([
        ('customer', 'Customer'),
        ('admin', 'Admin')
    ])
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    username = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    join_date = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    password = db.Column(db.String(255))
    role = db.Column(db.Enum(*ROLE, name='role_types', native_enum=False),
                     index=True, nullable=False, server_default='customer')
    orders = db.relationship('Order', backref='user', lazy=True)

    def __repr__(self):
        return f'<User: {self.name}>'


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    category = db.Column(db.String(20))
    price = db.Column(db.Numeric)
    stock = db.Column(db.Integer)
    description = db.Column(db.String(500))
    image = db.Column(db.String(100))

    orders = db.relationship('Order_Item', backref='product', lazy=True)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(20))
    first_name = db.Column(db.String(20))
    last_name = db.Column(db.String(20))
    phone_number = db.Column(db.Integer)
    email = db.Column(db.String(50))
    address = db.Column(db.String(100))
    city = db.Column(db.String(100))
    state = db.Column(db.String(20))
    country = db.Column(db.String(20))
    postal_code = db.Column(db.Integer)
    order_date = db.Column(db.DateTime)
    status = db.Column(db.String(10))
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    items = db.relationship('Order_Item', backref='order', lazy=True)

    def order_total(self):
        order_total_value = db.session.query(db.func.sum(Order_Item.quantity * Product.price)).join(Product).filter(
            Order_Item.order_id == self.id).scalar()
        if order_total_value:
            if order_total_value > 100:
                return order_total_value
            else:
                return order_total_value + 100
        else:
            return 0

    def quantity_total(self):
        return db.session.query(db.func.sum(Order_Item.quantity)).filter(Order_Item.order_id == self.id).scalar()


class Order_Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer)


class Contact(db.Model):
    message_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    email = db.Column(db.String(50))
    message = db.Column(db.String(500))
    status = db.Column(db.String(20))


class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(20))
    last_name = db.Column(db.String(20))
    phone_number = db.Column(db.Integer)
    email = db.Column(db.String(50))
    address = db.Column(db.String(100))
    city = db.Column(db.String(100))
    state = db.Column(db.String(20))
    country = db.Column(db.String(20))
    postal_code = db.Column(db.Integer)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

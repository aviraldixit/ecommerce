from app import app, db, photos
from forms import RegisterForm, LoginForm, ContactForm, AddProduct, AddToCart, Checkout, UpdateProfileForm
from flask import render_template, redirect, url_for, request, abort, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import login_required, login_user, current_user, logout_user
from models import User, Product, Order, Order_Item, Contact, Address
from send_mail import send_contact_email, send_registration_email, send_pay_confirmation_email
from sqlalchemy.exc import IntegrityError
from sqlalchemy import or_, and_, desc, asc
import random
import stripe

admin_list = ['adminuser@admin.com', '']


# ------------------- Fetch Number of Items in Cart-----------------------

def fetch_no_of_cart_items():
    quantity_total = 0
    if current_user.is_authenticated:
        cart_key = 'cart' + str(current_user.id)
        products, grand_total, grand_total_plus_shipping, quantity_total = handle_cart(cart_key)
    return quantity_total


# -----------------Home Route------------------------------

@app.route('/')
def index():
    # session[cart_key] = []
    return redirect(url_for('viewproducts', page_num=1))


@app.route('/home')
def home():
    no_of_cart_items = fetch_no_of_cart_items()
    return render_template('index.html', logged_in_user=current_user, no_of_cart_items=no_of_cart_items)


@app.route('/all-products')
def new_user():
    return render_template('products.html')


# ---------------------------------------------------------


# -------------------User Routes----------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            print(f'Logging User with userName: {form.email.data} and password: {form.password.data}')
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                user.last_login = datetime.now()
                db.session.add(user)
                db.session.commit()
                return redirect(url_for('viewproducts', page_num=1))
            else:
                flash('Invalid Username or Password', 'danger')
        else:
            flash('This email is not registered', 'warning')
        return render_template('login.html', form=form)
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        user_str = email.split('@')
        user_name = user_str[0]
        if email not in admin_list:
            new_user = User(name=name, username=user_name, email=email, password=hashed_password,
                            join_date=datetime.now())
        else:
            new_user = User(name=name, username=user_name, email=email, password=hashed_password,
                            join_date=datetime.now(), role='admin')
        try:
            db.session.add(new_user)
            db.session.commit()
            send_registration_email(new_user)
            login_user(new_user)
            print("User Entered with name: {} email: {} and password: {}".format(name, email, password))
            return redirect(url_for('viewproducts', page_num=1))
        except IntegrityError:
            db.session.rollback()
            flash('User is already registered with this email', 'warning')
            return render_template('register.html', form=form)
    return render_template('register.html', form=form)


# ----------------------------------------------------------------

# -------------------Product Routes-------------------------------

@app.route('/viewproducts/<int:page_num>')
def viewproducts(page_num):
    no_of_cart_items = fetch_no_of_cart_items()
    products = Product.query.paginate(per_page=5, page=page_num, error_out=True)
    return render_template('viewproducts.html', products=products, page_flag='all', no_of_cart_items=no_of_cart_items)


@app.route('/view-products-by-category/<category>,<int:page_num>')
def view_products_by_category(category, page_num):
    no_of_cart_items = fetch_no_of_cart_items()
    products = Product.query.filter_by(category=category).paginate(per_page=2, page=page_num, error_out=True)

    return render_template('viewproducts.html', products=products, category=category, page_flag='category',
                           no_of_cart_items=no_of_cart_items)


@app.route('/view-products-by-price/<int:page_num>', methods=['GET', 'POST'])
def view_products_by_price(page_num):
    no_of_cart_items = fetch_no_of_cart_items()
    if request.method == 'POST':
        min_value = int(request.form.get('min_value'))
        max_value = int(request.form.get('max_value'))
        session['min'] = min_value
        session['max'] = max_value
    else:
        min_value = session.get('min', 0)
        max_value = session.get('max', 2000)
    print('##############################################')
    print(f'Minimum value selected by user: {min_value} and Maximum value selected by user: {max_value}')
    print('##############################################')
    products = Product.query.filter(Product.price.between(min_value, max_value)).paginate(per_page=5, page=page_num,
                                                                                          error_out=True)

    return render_template('viewproducts.html', products=products, page_flag='price', no_of_cart_items=no_of_cart_items)


@app.route('/product/<id>')
def product(id):
    no_of_cart_items = fetch_no_of_cart_items()
    product_for_id = Product.query.filter_by(id=id).first()
    form = AddToCart()
    return render_template('view-product.html', product=product_for_id, form=form, no_of_cart_items=no_of_cart_items)


# ------------------ Adding Product in Cart --------------------

def handle_cart(cart_key):
    products = []
    grand_total = 0
    count = 0
    quantity_total = 0

    for item in session.get(cart_key, []):
        cart_product = Product.query.filter_by(id=item['id']).first()

        quantity = int(item['quantity'])
        total = quantity * cart_product.price
        grand_total += total

        quantity_total += quantity

        products.append(
            {'id': cart_product.id, 'name': cart_product.name, 'description': cart_product.description,
             'price': cart_product.price,
             'image': cart_product.image,
             'quantity': quantity, 'total': total, 'index': count})
        count += 1

    shipping_charge = 100

    if grand_total > 100:
        shipping_charge = 0

    grand_total_plus_shipping = grand_total + shipping_charge

    return products, grand_total, grand_total_plus_shipping, quantity_total


@app.route('/quick-add/<id>')
@login_required
def quick_add(id):
    requested_product = Product.query.filter_by(id=id).first()
    if requested_product.stock > 0:
        cart_key = 'cart' + str(current_user.id)
        if cart_key not in session:
            session[cart_key] = []
        update_flag = False

        if not session[cart_key]:
            session[cart_key].append({'id': id, 'quantity': 1})
            update_flag = True
        else:
            for item in session[cart_key]:
                if item['id'] == id:
                    quantity = item['quantity']
                    item_dict = {'id': id, 'quantity': quantity + 1}
                    session[cart_key].append(item_dict)
                    session[cart_key].remove(item)
                    update_flag = True
                    break

        if not update_flag:
            session[cart_key].append({'id': id, 'quantity': 1})

        session.modified = True
        flash('Product successfully added to the cart', 'success')
    else:
        flash('Oops Last one just got sold :(', 'danger')

    return redirect(url_for('viewproducts', page_num=1))


@app.route('/add-to-cart', methods=['POST'])
@login_required
def add_to_cart():
    cart_key = 'cart' + str(current_user.id)
    if cart_key not in session:
        session[cart_key] = []
    update_flag = False

    form = AddToCart()

    if form.validate_on_submit():
        if not session[cart_key]:
            session[cart_key].append({'id': form.id.data, 'quantity': form.quantity.data})
            update_flag = True
        else:
            for item in session[cart_key]:
                if item['id'] == form.id.data:
                    quantity = item['quantity']
                    item_dict = {'id': form.id.data, 'quantity': form.quantity.data + quantity}
                    session[cart_key].append(item_dict)
                    session[cart_key].remove(item)
                    update_flag = True
                    break

        if not update_flag:
            session[cart_key].append({'id': form.id.data, 'quantity': form.quantity.data})

        session.modified = True
        flash('Product successfully added to the cart', 'success')

    return redirect(url_for('viewproducts', page_num=1))


@login_required
@app.route('/cart')
def cart():
    cart_key = 'cart' + str(current_user.id)
    products, grand_total, grand_total_plus_shipping, quantity_total = handle_cart(cart_key)

    return render_template('cart.html', products=products, grand_total=grand_total,
                           grand_total_plus_shipping=grand_total_plus_shipping, quantity_total=quantity_total,
                           no_of_cart_items=quantity_total)


@app.route('/remove-from-cart/<index>')
@login_required
def remove_from_cart(index):
    cart_key = 'cart' + str(current_user.id)
    del session[cart_key][int(index)]
    session.modified = True
    return redirect(url_for('cart'))


@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart_key = 'cart' + str(current_user.id)
    form = Checkout()
    prev_order_flag = False
    prev_order = Order.query.filter(and_(Order.customer_id == current_user.id, Order.status == 'PAID')).order_by(
        asc(Order.order_date)).first()
    if request.method == 'GET':
        saved_addresses = Address.query.filter(Address.customer_id == current_user.id).first()
    else:
        saved_addresses = None
    if saved_addresses:
        prev_order_flag = True

    products, grand_total, grand_total_plus_shipping, quantity_total = handle_cart(cart_key)
    if form.validate_on_submit():
        if current_user.is_authenticated:
            customer_id = current_user.id
            if not prev_order:
                new_address = Address(first_name=form.first_name.data, last_name=form.last_name.data,
                                      phone_number=form.phone_number.data,
                                      email=form.email.data, address=form.address.data, city=form.city.data,
                                      state=form.state.data,
                                      country=form.country.data, postal_code=form.postal_code.data,
                                      customer_id=customer_id)
                db.session.add(new_address)
            elif form.default_address.data is not None and form.default_address.data:
                new_address = Address(first_name=form.first_name.data, last_name=form.last_name.data,
                                      phone_number=form.phone_number.data,
                                      email=form.email.data, address=form.address.data, city=form.city.data,
                                      state=form.state.data,
                                      country=form.country.data, postal_code=form.postal_code.data,
                                      customer_id=customer_id)
                db.session.add(new_address)
            buy_order = Order(first_name=form.first_name.data, last_name=form.last_name.data,
                              phone_number=form.phone_number.data,
                              email=form.email.data, address=form.address.data, city=form.city.data,
                              state=form.state.data,
                              country=form.country.data, postal_code=form.postal_code.data, order_date=datetime.now(),
                              customer_id=customer_id)
            db.session.add(buy_order)
            db.session.commit()

            return render_template('payment.html', order=buy_order, grand_total=grand_total,
                                   grand_total_plus_shipping=grand_total_plus_shipping,
                                   quantity_total=quantity_total)
    return render_template('checkout.html', form=form, no_of_cart_items=quantity_total, buy_flag=False,
                           address=saved_addresses, prev_order_flag=prev_order_flag)


@app.route('/buy-now/<product_id>', methods=['GET', 'POST'])
def buy_now(product_id):
    form = Checkout()
    if current_user.is_authenticated:
        session_key = 'buy'
        session[session_key] = product_id
        prev_order_flag = False
        prev_order = Order.query.filter(and_(Order.customer_id == current_user.id, Order.status == 'PAID')).order_by(
            asc(Order.order_date)).first()
        if request.method == 'GET':
            saved_addresses = Address.query.filter(Address.customer_id == current_user.id).first()
        else:
            saved_addresses = None
        if saved_addresses:
            prev_order_flag = True
        if form.validate_on_submit():
            buy_product = Product.query.filter_by(id=product_id).first()
            shipping_price = 100
            if buy_product.price > 100:
                shipping_price = 0
            grand_total = buy_product.price
            grand_total_plus_shipping = grand_total + shipping_price
            quantity_total = 1
            customer_id = current_user.id
            if not prev_order:
                new_address = Address(first_name=form.first_name.data, last_name=form.last_name.data,
                                      phone_number=form.phone_number.data,
                                      email=form.email.data, address=form.address.data, city=form.city.data,
                                      state=form.state.data,
                                      country=form.country.data, postal_code=form.postal_code.data,
                                      customer_id=customer_id)
                db.session.add(new_address)
            elif form.default_address.data is not None and form.default_address.data:
                new_address = Address(first_name=form.first_name.data, last_name=form.last_name.data,
                                      phone_number=form.phone_number.data,
                                      email=form.email.data, address=form.address.data, city=form.city.data,
                                      state=form.state.data,
                                      country=form.country.data, postal_code=form.postal_code.data,
                                      customer_id=customer_id)
                db.session.add(new_address)
            buy_order = Order(first_name=form.first_name.data, last_name=form.last_name.data,
                              phone_number=form.phone_number.data,
                              email=form.email.data, address=form.address.data, city=form.city.data,
                              state=form.state.data,
                              country=form.country.data, postal_code=form.postal_code.data, order_date=datetime.now(),
                              customer_id=customer_id)
            db.session.add(buy_order)
            db.session.commit()

            return render_template('payment.html', order=buy_order, grand_total=grand_total,
                                   grand_total_plus_shipping=grand_total_plus_shipping,
                                   quantity_total=quantity_total)
        return render_template('checkout.html', form=form, buy_flag=True, address=saved_addresses,
                               prev_order_flag=prev_order_flag, product_id=product_id)
    else:
        session_key = 'buy'
        session[session_key] = product_id

        if form.validate_on_submit():
            buy_product = Product.query.filter_by(id=product_id).first()
            shipping_price = 100
            if buy_product.price > 100:
                shipping_price = 0
            grand_total = buy_product.price
            grand_total_plus_shipping = grand_total + shipping_price
            quantity_total = 1
            buy_order = Order(first_name=form.first_name.data, last_name=form.last_name.data,
                              phone_number=form.phone_number.data,
                              email=form.email.data, address=form.address.data, city=form.city.data,
                              state=form.state.data,
                              country=form.country.data, postal_code=form.postal_code.data, order_date=datetime.now(),
                              customer_id=None)
            db.session.add(buy_order)
            db.session.commit()

            return render_template('payment.html', order=buy_order, grand_total=grand_total,
                                   grand_total_plus_shipping=grand_total_plus_shipping,
                                   quantity_total=quantity_total)

        return render_template('checkout.html', form=form, buy_flag=True, address=None, prev_order_flag=False,
                               product_id=product_id)


# --------------------- Admin Routes -----------------------------


@app.route('/admin/view-products/<int:page_num>')
def view_all_products(page_num):
    products = Product.query.paginate(per_page=10, page=page_num, error_out=True)

    return render_template('admin/view-all-products.html', admin=True, products=products)


@app.route('/admin/view-orders/<int:page_num>')
def view_all_orders(page_num):
    orders = Order.query.filter(or_(Order.status == 'PAID', Order.status == 'CANCELLED')).order_by(
        desc(Order.order_date)).paginate(per_page=10, page=page_num, error_out=True)

    return render_template('admin/view-all-orders.html', admin=True, orders=orders)


@app.route('/admin/order/<order_id>')
def order(order_id):
    filter_order = Order.query.filter_by(id=int(order_id)).first()

    return render_template('admin/view-order.html', order=filter_order, admin=True)


@app.route('/admin/add', methods=['GET', 'POST'])
def add():
    if current_user.role == 'admin':
        form = AddProduct()
        if form.validate_on_submit():
            image_name = 'images/' + form.image.data.filename
            photos.url(photos.save(form.image.data))

            new_product = Product(name=form.name.data, category=form.category.data, price=form.price.data,
                                  stock=form.stock.data, description=form.description.data, image=image_name)

            db.session.add(new_product)
            db.session.commit()
            return redirect(url_for('admin'))
        return render_template('admin/add-product.html', admin=True, form=form)
    else:
        flash('You are not allowed to access this page', 'warning')
        return render_template('index.html', logged_in_user=current_user)


@app.route('/admin/update', methods=['GET', 'POST'])
def update():
    if current_user.role == 'admin':
        if request.method == 'POST':
            product_form_dict = dict(request.form)
            product_name = product_form_dict['name']
            product_dict = {}
            if product_form_dict['category']:
                product_dict['category'] = product_form_dict['category']
            if product_form_dict['price']:
                product_dict['price'] = product_form_dict['price']
            if product_form_dict['description']:
                product_dict['description'] = product_form_dict['description']
            if request.files.get('image').filename:
                image_name = 'images/' + request.files.get('image').filename
                product_dict['image'] = image_name
                photos.url(photos.save(request.files.get('image')))

            if product_dict:
                if product_name:
                    update_product = Product.query.filter_by(name=product_name).first()
                    if product_form_dict['stock']:
                        existing_stock = update_product.stock
                        product_dict['stock'] = int(product_form_dict['stock']) + existing_stock
                    if update_product:
                        Product.query.filter_by(name=product_name).update(product_dict)
                        db.session.commit()
                        flash('Product was successfully updated', 'success')
                    else:
                        flash('No Product was found with the requested name', 'warning')
                else:
                    flash('Product Name is mandatory', 'warning')
            else:

                flash('No update was requested', 'warning')
            return redirect(url_for('admin'))
        return render_template('admin/update-product.html', admin=True, flag='update')
    else:
        flash('You are not allowed to access this page', 'warning')
        return render_template('index.html', logged_in_user=current_user)


@app.route('/admin/delete', methods=['GET', 'POST'])
def delete():
    if current_user.role == 'admin':
        if request.method == 'POST':
            product_name = request.form.get('name')

            if product_name:
                update_product = Product.query.filter_by(name=product_name).first()
                if update_product:
                    db.session.delete(update_product)
                    db.session.commit()
                    flash('Product was successfully deleted', 'danger')
                else:
                    flash('No Product was found with the requested name', 'warning')
            else:
                flash('Product Name is mandatory', 'warning')
            return redirect(url_for('admin'))
        return render_template('admin/update-product.html', admin=True, flag='delete')
    else:
        flash('You are not allowed to access this page', 'warning')
        return render_template('index.html', logged_in_user=current_user)


# --------------------- Customer Routes -----------------------------------

@app.route('/customer/orders/<int:page_num>')
@login_required
def customer_order(page_num):
    no_of_cart_items = fetch_no_of_cart_items()
    my_order = Order.query.filter(and_(Order.customer_id == current_user.id, or_(
        Order.status == 'PAID', Order.status == 'CANCELLED'))).order_by(
        desc(Order.order_date)).paginate(per_page=1, page=page_num, error_out=True)

    print(my_order)

    return render_template('customer/customer-order.html', user=current_user, orders=my_order,
                           no_of_cart_items=no_of_cart_items)


@app.route('/customer/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user
    form = UpdateProfileForm()
    if form.validate_on_submit():
        print(form.name.data)
        print(form.email.data)
        print(form.password.data)
        if form.name.data != user.name:
            User.query.filter_by(id=user.id).update({'name': form.name.data})
            db.session.commit()
            flash('Name successfully changed', 'success')
        if form.email.data != user.email:
            User.query.filter_by(id=user.id).update({'email': form.email.data})
            db.session.commit()
            flash('Email successfully changed', 'success')
        if user.password != form.password.data:
            User.query.filter_by(id=user.id).update(
                {'password': generate_password_hash(form.password.data, method='sha256')})
            db.session.commit()
            flash('Password successfully changed', 'success')
            logout_user()
            return redirect(url_for('login'))
        return render_template('index.html', logged_in_user=current_user)

    return render_template('customer/update-profile.html', form=form, logged_in_user=current_user)


# ---------------Contact Route-----------------------------------

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        message = form.message.data
        new_contact = Contact(name=name, email=email, message=message, status='PENDING')
        db.session.add(new_contact)
        db.session.commit()
        send_contact_email(name, email, message)
        flash('Thanks for Reaching out to us, we will contact you shortly', 'success')
        return redirect(url_for('index'))
    return render_template('contact.html', form=form)


# ---------------About us Route-----------------------------------

@app.route('/about')
def about():
    return render_template('about.html')


# -------------------------Payment Handling Piece ---------------------


@app.route("/config")
def get_publishable_key():
    stripe_config = {"publicKey": app.config[
        'STRIPE_PUBLIC_KEY']}
    return jsonify(stripe_config)


@app.route("/create-checkout-session/<order_id>")
def create_checkout_session(order_id):
    products = []
    product_id = ''
    session['EXPIRE_FLAG'] = True
    if 'buy' in session and session.get('buy'):
        product_id = session.get('buy')
        cart_product = Product.query.filter_by(id=product_id).first()
        shipping_price = 100
        if cart_product.price > 100:
            shipping_price = 0
        grand_total = cart_product.price
        grand_total_plus_shipping = grand_total + shipping_price
    else:
        cart_key = 'cart' + str(current_user.id)
        products, grand_total, grand_total_plus_shipping, quantity_total = handle_cart(cart_key)
    amount = str(grand_total_plus_shipping * 100)
    domain_url = request.host_url
    stripe.api_key = app.config['STRIPE_SECRET_KEY']

    try:
        # Create new Checkout Session for the order
        # Other optional params include:
        # [billing_address_collection] - to display billing address details on the page
        # [customer] - if you have an existing Stripe Customer ID
        # [payment_intent_data] - lets capture the payment later
        # [customer_email] - lets you prefill the email input in the form
        # For full details see https:#stripe.com/docs/api/checkout/sessions/create

        # ?session_id={CHECKOUT_SESSION_ID} means the redirect will have the session ID set as a query param
        checkout_session = stripe.checkout.Session.create(
            success_url=domain_url + "payment_success?session_id={CHECKOUT_SESSION_ID}&order_id=" + order_id,
            cancel_url=domain_url + "payment_cancelled?order_id=" + order_id,
            payment_method_types=["card"],
            mode="payment",
            line_items=[
                {
                    "name": "Almond Order",
                    "quantity": 1,
                    "currency": "inr",
                    "amount": amount,
                }
            ]
        )
        # Product update

        created_order = Order.query.filter_by(id=order_id).first()

        ref1 = str(random.randint(100, 999))
        ref2 = ''.join([random.choice('ABCDELMNOPWXYZ') for _ in range(3)])
        ref3 = str(random.randint(100, 999))
        reference_no = ref1 + '-' + ref2 + '-' + ref3
        print(f'Final Reference number: {reference_no}')

        created_order.reference = reference_no
        created_order.status = 'PENDING'

        if products:
            for cart_product in products:
                order_item = Order_Item(quantity=cart_product['quantity'], product_id=cart_product['id'])
                created_order.items.append(order_item)

                Product.query.filter_by(id=cart_product['id']).update(
                    {'stock': Product.stock - cart_product['quantity']})
        else:
            order_item = Order_Item(quantity=1, product_id=product_id)
            created_order.items.append(order_item)

            Product.query.filter_by(id=product_id).update({'stock': Product.stock - 1})

        db.session.add(created_order)
        db.session.commit()

        return jsonify({"sessionId": checkout_session["id"]})
    except Exception as e:
        return jsonify(error=str(e)), 403


@app.route("/webhook", methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, 'SOME SECRET KEY'
        )

    except ValueError as e:
        # Invalid payload
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return 'Invalid signature', 400

    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']

        # Fulfill the purchase...
        handle_checkout_session(session)

    return 'Success', 200


def handle_checkout_session(session):
    print("Payment was successful.")
    # TODO: run some custom code here


@app.route("/payment_success")
def success():
    if 'EXPIRE_FLAG' in session:
        if not session['EXPIRE_FLAG']:
            flash('Link Expired', 'danger')
            return redirect(url_for('index'))
    else:
        flash('Link Expired', 'danger')
        return redirect(url_for('index'))
    cart_key = ''
    if current_user.is_authenticated:
        cart_key = 'cart' + str(current_user.id)

    print('Payment success')
    order_id = request.args.get('order_id', '')
    if order_id:
        Order.query.filter_by(id=order_id).update({'status': 'PAID'})
        confirmed_order = Order.query.filter_by(id=order_id).first()
        order_reference = confirmed_order.reference
        db.session.commit()

        if current_user.is_authenticated:
            user_name = current_user.name
            user_email = current_user.email
        else:
            user_name = confirmed_order.first_name + ' ' + confirmed_order.last_name
            user_email = confirmed_order.email

        send_pay_confirmation_email(user_name, confirmed_order, user_email)

        if cart_key in session:
            session[cart_key] = []
        if 'buy' in session:
            session['buy'] = None
        session.modified = True
        session['EXPIRE_FLAG'] = False
    return render_template("payment_success.html", reference=order_reference)


@app.route("/payment_cancelled")
def cancelled():
    if 'EXPIRE_FLAG' in session:
        if not session['EXPIRE_FLAG']:
            flash('Link Expired', 'danger')
            return redirect(url_for('index'))
    else:
        flash('Link Expired', 'danger')
        return redirect(url_for('index'))
    order_id = request.args.get('order_id', '')
    if order_id:
        Order.query.filter_by(id=order_id).update({'status': 'CANCELLED'})
        db.session.commit()
    session['EXPIRE_FLAG'] = False
    return render_template("index.html")

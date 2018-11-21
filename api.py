from flask import Flask, jsonify
from flask_restful import Resource, Api, reqparse, fields, marshal
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, verify_jwt_in_request, get_jwt_claims, jwt_required
from functools import wraps
import sys, json, datetime
from flask_cors import CORS


app = Flask(__name__)
api = Api(app)

# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:020601@127.0.0.1/App'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:020601tri@portofolio.cqca0rvctn3a.ap-southeast-1.rds.amazonaws.com/portofolio'
app.config['SQLALCHEMY_ECHO'] = True
app.config['JWT_SECRET_KEY'] = "jwt_secret_key"

db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)
jwt = JWTManager(app)

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt_claims()
        if claims["type"] != "admin":
            # if not admin
            return {'message':'FORBIDDEN'}, 403, {'Content-Type': 'application/json'}
        else:
            # if admin
            return fn(*args, **kwargs)
    return wrapper

def user_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt_claims()
        if claims['type'] != 'user':
            # if not user
            return {'message':'FORBIDDEN'}, 403, {'Content-Type': 'application/json'}
        else:
            # if user
            return fn(*args, **kwargs)
    return wrapper

product_fields = {
    "id" : fields.Integer,
    "seller_id" : fields.Integer,
    "users.name": fields.String,
    "users.username": fields.String,
    "users.email": fields.String,
    "product_name" : fields.String,
    "desc" : fields.String,
    "price": fields.Integer,
    "brand" : fields.String,
    "category" : fields.String,
    "image" : fields.String,
    "show_status" : fields.Boolean,
    "created_at" : fields.String,
    "updated_at" : fields.String
}

category_fields = {
    "id" : fields.Integer,
    "category": fields.String
}

user_fields={
    "id": fields.Integer,
    "name": fields.String, 
    "username": fields.String,
    "email": fields.String,
    "type": fields.String,
    "status":fields.Boolean,
    "url_image": fields.String,
    "created_at": fields.String,
    "updated_at": fields.String
}

cart_fields={
     "id": fields.Integer,
    "buyer_id": fields.Integer,
    "product_id": fields.Integer,
    "seller_id": fields.Integer,
    "quantity": fields.Integer,
    "price": fields.Integer,
    "cart_status": fields.Boolean,
    "created_at": fields.String,
    "updated_at": fields.String

}

# ************** M O D E L ************** #
class Users(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(255), nullable = False)
    username = db.Column(db.String(255),unique=True, nullable = False)
    email = db.Column(db.String(255), unique=True, nullable = False)
    password = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(30), nullable=False, default="user")
    status = db.Column(db.Boolean, default=1)
    url_image = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default= db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default= db.func.current_timestamp())
    # relationship
    products = db.relationship('Products', backref='users')

    def __repr__(self):
        return '<Users %r>' % self.id

class Carts(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    buyer_id = db.Column(db.Integer, nullable = False)
    product_id = db.Column(db.Integer, nullable = False)
    seller_id = db.Column(db.Integer, nullable = False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    price = db.Column(db.Integer)
    cart_status = db.Column(db.Boolean, nullable = False, default=0)
    created_at = db.Column(db.DateTime, default= db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default= db.func.current_timestamp())

class Products(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    product_name = db.Column(db.String(255), nullable = False)
    desc = db.Column(db.String(5000))
    price = db.Column(db.Integer, nullable=False)
    brand = db.Column(db.String(255))
    category = db.Column(db.String(255), nullable = False)
    image = db.Column(db.String(500))
    show_status = db.Column(db.Boolean, nullable = False, default=1)
    created_at = db.Column(db.DateTime, default= db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default= db.func.current_timestamp())
    seller_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable = False)

    def __repr__(self):
        return '<Books %r>' % self.id

class Categories(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    category = db.Column(db.String(255), nullable = False, unique = True)

# ************** M O D E L ************** #

class ProductResources(Resource):

    @user_required
    def get(self, id=None):
        if id != None:

            identity = get_jwt_identity()
            
            qry = Products.query

            qry=qry.filter_by(seller_id = identity)

            qry = qry.filter_by(id = id)

            rows = []

            for row in qry.all():
                rows.append(marshal(row, product_fields))
            print(rows)
            if rows == []:
                return {'message': 'DATA NOT FOUND'}, 404
            return {
                "message": "SUCCESS",
                "results" : rows
            }, 200

        parser=reqparse.RequestParser()
        parser.add_argument('p',type=int,location='args',default=1)
        parser.add_argument('rp',type=int,location='args',default=25)
        parser.add_argument('product_name',type=str,location='args')
        parser.add_argument('brand',type=str,location='args')
        parser.add_argument('category',type=str,location='args')
        parser.add_argument('orderBy',location='args',help='invalid order by',choices=('id','product_name','brand','created_at','updated_at'))
        parser.add_argument('sort',location='args',help='invalid sort',choices=('desc','asc'))
        args=parser.parse_args()

        # get products with seller id
        qry = Products.query

        identity = get_jwt_identity()      
        qry=qry.filter_by(seller_id = identity) 

        # ================   filter    ================      
        # by Title
        if args['product_name'] is not None:
            qry = qry.filter(Products.product_name.like("%"+args["product_name"]+"%"))
       
       # by Author
        if args['brand'] is not None:
            qry = qry.filter(Products.brand.like("%"+args["brand"]+"%"))

        # by Category
        if args['category'] is not None:
            qry = qry.filter_by(category = args['category']) 

        # ================   order    =================    
        sort = args['sort']
        if args['orderBy']=='id':
            qry=qry.order_by('id %s'%(sort))
        elif args['orderBy']=='product_name':
            qry=qry.order_by('product_name %s'%(sort))
        elif args['orderBy']=='brand':    
            qry=qry.order_by('brand %s'%(sort))
        elif args['orderBy']=='created_at':     
            qry=qry.order_by('created_at %s'%(sort)) 
        elif args['orderBy']=='updated_at':     
            qry=qry.order_by('updated_at %s'%(sort))     

        #================= pagination =================
        if args['p']==1:
            offset=0
        else:
            # logic
            offset=(args['p']*args['rp'])-args['rp']

        qry=qry.limit(args['rp']).offset(offset)
        rows=[]
        for row in qry.all():
            rows.append(marshal(row,product_fields))        

        output = { "page": args['p'], "per_page": args['rp'], "Result": rows }
        #  ****************************rev*********************************************       
        return {'message':"SUCCESS",'result':output} ,200

    @user_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("product_name", type= str, help= "PRODUCT NAME IS EMPTY", location= "json", required= True)
        parser.add_argument("desc", type= str, help= "DESCRIPTION IS NOT STRING", location= "json")
        parser.add_argument("price", type= int, help= "PRICE IS EMPTY", location= "json", required= True)
        parser.add_argument("brand", type= str, help= "BRAND IS NOT STRING", location= "json")
        parser.add_argument("category", type= str, help= "CATEGORY IS EMPTY", location= "json", required= True)
        parser.add_argument("image", type= str, help= "IMAGE IS NOT STRING", location= "json")

        args = parser.parse_args()
        identity = get_jwt_identity()
        # try:
        add_product = Products(
            seller_id= identity, 
            product_name=args['product_name'],
            desc=args['desc'],
            price=args['price'],
            brand=args['brand'],
            category=args['category'], 
            image=args['image']
        )

        db.session.add(add_product)
        db.session.commit()

        product = marshal(add_product, product_fields)

        return {
            "message" : "PRODUCT INPUT SUCCESS",
            "product": product
        }, 200

        # except :
        #     return {'message' : 'BAD REQUEST'}, 400

    @user_required
    def put(self,id):
        parser = reqparse.RequestParser()
        parser.add_argument('product_name', type = str, help='product_name must be string type',location='json')
        parser.add_argument('desc', type = str, help='desc must be string type',location='json')
        parser.add_argument('price', type = int, help='price status must be integer type',location='json')
        parser.add_argument('brand', type = str, help='brand must be string type',location='json')
        parser.add_argument('category', type = str, help='category must be string type',location='json')
        parser.add_argument('image', type = str, help='image must be string type',location='json')

        args = parser.parse_args()
        
        qry = Products.query.filter_by(id = id).first()
        
        if qry == None :
            return {'message': 'PRODUCT NOT FOUND'}, 404

        else:
            
            # update the data
            if args["product_name"] != None:
                qry.product_name= args["product_name"]
            if args["desc"] != None:
                qry.desc= args["desc"]
            if args["price"] != None:
                qry.price= args["price"]
            if args["brand"] != None:
                qry.brand= args["brand"]
            if args["category"] != None:
                qry.category= args["category"]
            if args["image"] != None:
                qry.image= args["image"]

            qry.updated_at = db.func.current_timestamp()
                    
            db.session.add(qry)
            db.session.commit()
            return {
                "message": "PRODUCT UPDATE SUCCESS",
                "product": marshal(qry, product_fields)
            } ,200

    @user_required
    def delete(self, id):
        qry = Products.query
        qry = qry.filter_by(id = id)

        rows = (marshal(qry.all(), product_fields))

        if len(rows) == 0 :
            return {'message':'PRODUCT NOT FOUND'},404
        else:
            qry = qry.delete()
            db.session.commit()
            return {'message': 'PRODUCT DELETED'}, 200

class CategoryResources(Resource):
    def get(self, id=None):
        if id != None:
            qry = Categories.query

            qry = qry.filter_by(id = id)

            rows = []

            for row in qry.all():
                rows.append(marshal(row, category_fields))

            if rows == []:
                return {'message': 'DATA NOT FOUND'}, 404
            return {
                "message": "SUCCESS",
                "results" : rows
            }, 200

        qry = Categories.query

        parser=reqparse.RequestParser()
        parser.add_argument('orderBy',location='args',help='invalid order by',choices=('id','category'))
        parser.add_argument('sort',location='args',help='invalid sort',choices=('desc','asc'))
       
        args=parser.parse_args()

        # ================   order    =================    
        sort = args['sort']
        if args['orderBy']=='id':
            qry=qry.order_by('id %s'%(sort))
        elif args['orderBy']=='category':
            qry=qry.order_by('category %s'%(sort))

        rows=[]
        for row in qry.all():
            rows.append(marshal(row,category_fields))        

        ans = []
        for data in rows:
            ans.append(data["category"])
        #  ****************************rev*********************************************       
        return {'message':"SUCCESS",'result': ans} ,200

    @admin_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("category", type= str, help= "CATEGORY IS EMPTY", location= "json", required= True)
        args = parser.parse_args()
        try:
            add_category = Categories(
                category=args['category']
            )

            db.session.add(add_category)
            db.session.commit()

            category = marshal(add_category, category_fields)

            return {
                'message' : 'CATEGORY INPUT SUCCESS',
                'results': category
            }, 200

        except :
            return {'message' : 'BAD REQUEST'}, 400

    @admin_required
    def put(self,id):
        parser = reqparse.RequestParser()
        parser.add_argument('category', type = str, help='category must be string type',location='json')

        args = parser.parse_args()
        
        qry = Categories.query  
        qry = qry.filter_by(id = id)
        
        rows = (marshal(qry.first(), category_fields))

        if len(rows) == 0 :
            return {'message': 'CATEGORY NOT FOUND'}, 404
        else:

            qry.update({'category':args['category']})
            db.session.commit()
            rows = (marshal(qry.all(), category_fields))
            return rows,200

    @admin_required
    def delete(self, id):
        qry = Categories.query
        qry = qry.filter_by(id = id)

        rows = (marshal(qry.all(), category_fields))

        if len(rows) == 0 :
            return {'message':'CATEGORY NOT FOUND'},404
        else:
            qry = qry.delete()
            db.session.commit()
            return {'message': 'CATEGORY DELETED'}, 200

class ProductPublicResources(Resource):

    def get(self, id=None):
        if id != None:
            
            qry = Products.query

            qry = qry.filter_by(id = id)

            rows = []

            for row in qry.all():
                rows.append(marshal(row, product_fields))
            print(rows)
            if rows == []:
                return {'message': 'DATA NOT FOUND'}, 404
            return {
                "message": "SUCCESS",
                "results" : rows
            }, 200

        parser=reqparse.RequestParser()
        parser.add_argument('p',type=int,location='args',default=1)
        parser.add_argument('rp',type=int,location='args',default=25)
        parser.add_argument('product_name',type=str,location='args')
        parser.add_argument('brand',type=str,location='args')
        parser.add_argument('category',type=str,location='args')
        parser.add_argument('orderBy',location='args',help='invalid order by',choices=('id','product_name','brand','created_at','updated_at'))
        parser.add_argument('sort',location='args',help='invalid sort',choices=('desc','asc'))
        args=parser.parse_args()

        qry = Products.query

        # ================   filter    ================      
        # by product name
        if args['product_name'] is not None:
            qry = qry.filter(Products.product_name.like("%"+args["product_name"]+"%"))
       
       # by brand
        if args['brand'] is not None:
            qry = qry.filter(Products.brand.like("%"+args["brand"]+"%"))

        # by Category
        if args['category'] is not None:
            qry = qry.filter_by(category = args['category']) 

        # ================   order    =================    
        if args['sort'] is not None:
            sort = args['sort']
            if args['orderBy']=='id':
                qry=qry.order_by('id %s'%(sort))
            elif args['orderBy']=='product_name':
                qry=qry.order_by('product_name %s'%(sort))
            elif args['orderBy']=='brand':    
                qry=qry.order_by('brand %s'%(sort))
            elif args['orderBy']=='created_at':     
                qry=qry.order_by('created_at %s'%(sort)) 
            elif args['orderBy']=='updated_at':     
                qry=qry.order_by('updated_at %s'%(sort))     

        #================= pagination =================
        if args['p']==1:
            offset=0
        else:
            # logic
            offset=(args['p']*args['rp'])-args['rp']

        qry=qry.limit(args['rp']).offset(offset)
        rows=[]
        for row in qry.all():
            rows.append(marshal(row,product_fields))        

        output = { "page": args['p'], "per_page": args['rp'], "Result": rows }
        #  ****************************rev*********************************************       
        return {'message':"SUCCESS",'result':output} ,200
        
class RegisterResources(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type= str, location='json', required= True, help= 'name must be string and exist')
        parser.add_argument('username', type= str, location='json', required= True, help= 'username must be string and exist')
        parser.add_argument('email', type= str, location='json', required= True, help= 'email must be string and exist')
        parser.add_argument('password', type= str, location='json', required=True, help= 'password must be string and exist')
        parser.add_argument('type', type= str, location='json', required=False, help= 'type must be string')
        parser.add_argument('url_image', type= str, location='json', required=False, help= 'url_image must be string and exist')

        args = parser.parse_args()

        qry = Users.query.filter_by(username=args['username']).first()

        if qry != None:
            return {"message":"username has been used"}

        add_user = Users(
            name = args['name'], 
            username = args['username'], 
            email= args['email'], 
            password= args['password'], 
            type= args['type'],        
            url_image= args['url_image'], 
        )

        db.session.add(add_user)
        db.session.commit()

        # create token
        token = create_access_token(identity= add_user.id, expires_delta = datetime.timedelta(days=30))
        return {"message": "SUCCESS" , "token": token, "user": marshal(add_user, user_fields)}, 200

class LoginResources(Resource):
    # auth, just user with pelapak token can access this method 
    @user_required
    def get(self):
        # get user identity from token by claims 
        current_user = get_jwt_identity()

        # find data user by user identity (id users from token by claims)
        qty= Users.query.get(current_user)
        data = {
            "name": qty.name,
            "username": qty.username,
            "email": qty.email,
            "password": qty.password,
            "type": qty.type,
            "url_image": qty.url_image,
            "created_at": qty.created_at,
            "updated_at": qty.updated_at
        }
        return data, 200

    # method to get jwt token for pelapak already have account
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', location= 'json', required= True)
        parser.add_argument('password', location= 'json', required= True)

        args = parser.parse_args()

        # get data users by telephone and password
        qry = Users.query.filter_by( username= args['username'], password= args['password']).first()
        
        # check whether the user with the telephone and password entered already has an account
        if qry == None:
            # if not return 401
            return {"message": "UNAUTHORIZED"}, 401
        
        # if have account create token for him
        token = create_access_token(identity= qry.id, expires_delta = datetime.timedelta(days=30))

        # then return to him
        return {"token": token, "user": marshal(qry, user_fields)}, 200

class ProductAdminResources(Resource):
    @admin_required
    def put(self,id):
        parser = reqparse.RequestParser()
        parser.add_argument('show_status', type = bool, help='show status must be string type',location='json')

        args = parser.parse_args()
        
        qry = Products.query.filter_by(id = id)
        
        rows = (marshal(qry.first(), product_fields))

        if len(rows) == 0 :
            return {'message': 'PRODUCT NOT FOUND'}, 404
        else:

            qry.update({'show_status':args['show_status']})

            db.session.commit()
            rows = (marshal(qry.all(), product_fields))
            return {
                "message": "show status updated",
                "result": rows
            },200

class UserResources(Resource):

    @admin_required
    def get(self, id= None):
        # get identity from user token
        ans = {}
        ans["message"] = "SUCCESS"
        rows = []

        # if method get have id params
        if(id != None):
            # get data where id from params
            qry = Users.query.filter_by(id = id).first()
            # if not found data
            if(qry == None):
                # return message
                return {'message': 'Data not found !!!'}, 404
            # if found data
            rows = marshal(qry, user_fields)
            ans["data"] = rows
            # return data
            return ans, 200

        # if id params stil None (nothing data from id params), get all data on pelapak id 
        qry = Users.query
        
        for row in qry.all():
            # collect all data to rows
            rows.append(marshal(row, user_fields))
        
        ans["data"] = rows

        # return all data
        return ans, 200

    @admin_required
    def put(self, id):
        # get data where on id
        data = Users.query.filter_by(id = id).first()

        # if not have data
        if(data == None): 
            # return not found
            return {'message': 'Data not found !!!'}, 404

        parser = reqparse.RequestParser()
        parser.add_argument("name", type= str, help= 'name key must be an string and exist', location= 'json', required= False)
        parser.add_argument("username", type= str, help= 'username key must be an string', location= 'json', required= False)
        parser.add_argument("email", type= str, help= 'email must be an string', location= 'json', required= False)
        parser.add_argument("password", type= str, help= 'password must be an integer', location= 'json', required= False)
        parser.add_argument("url_image", type= str, help= 'url image must be an string', location= 'json', required= False)
        parser.add_argument("status", type= bool, help= 'status must be an string and exist', location= 'json', required= False)
        args = parser.parse_args()

        # update the data
        if args["name"] != None:
            data.name= args["name"]
        if args["username"] != None:
            data.username= args["username"]
        if args["email"] != None:
            data.email= args["email"]
        if args["password"] != None:
            data.password= args["password"]
        if args["url_image"] != None:
            data.url_image= args["url_image"]
        if args["status"] != None:
            data.status= args["status"]

        # update updatedAt field when update data
        data.updated_at = db.func.current_timestamp()
        
        db.session.add(data)
        db.session.commit()

        return {"message": "SUCCESS", "user": marshal(data, user_fields)}, 200

    @admin_required
    def delete(self, id):
        # get data
        data = Users.query.filter_by(id = id).first()

        #check if data exist
        if data == None:
            # return not found it nothing data
            return {'message': "Data not found!"}, 404

        db.session.delete(data)
        db.session.commit()
        return {'message': "SUCCESS"}, 200

class CartResources(Resource):

    def getProduct(self, id):
        qry = Products.query.filter_by(id = id).first()
        rows = marshal(qry, product_fields)

        return rows

    def getUser(self, id):
        qry = Users.query.filter_by(id = id).first()
        rows = marshal(qry, user_fields)
        
        return rows


    @user_required
    def get(self, id=None):
        qry = Carts.query

        identity = get_jwt_identity()
        parser=reqparse.RequestParser()

        ans = {}
        ans["message"] = "SUCCESS"
        ans["result"] = []
        rows = []

        parser.add_argument('filter',type=str,location='args', help="filter must be buyer or seller", choices=("buyer", "seller") )
        parser.add_argument('cart_status',type=str,location='args', help="cart_status must be bollean")
        # filter = seller or buyer
        args=parser.parse_args()

        if id != None:
            if args['filter'] == "seller":
                qry = qry.filter_by(seller_id = identity, product_id= id)

            elif args['filter'] == "buyer":
                qry = qry.filter_by(buyer_id = identity, product_id= id)
         
            if args["cart_status"] != None:
                if args['cart_status'] == "true" or args['cart_status'] == True:
                    args['cart_status'] = 1
                else:
                    args['cart_status'] = 0
                qry = qry.filter_by( cart_status = args["cart_status"])


            for row in qry.all():
            # collect all data to rows
                rows.append(marshal(row, cart_fields))

            rows[0]['product'] = self.getProduct(rows[0]["product_id"])
            rows[0]['buyer'] = self.getUser(rows[0]["buyer_id"])
            rows[0]['seller'] = self.getUser(rows[0]["seller_id"])
            ans['result'].append(rows[0])
            return ans, 200

        # ================   filter    ================      
        # by owner id
        if args['filter'] == "seller":
            qry = qry.filter_by(seller_id = identity)
        elif args['filter'] == "buyer":
            qry = qry.filter_by(buyer_id = identity)

        if args["cart_status"] != None:
            if args['cart_status'] == "true" or args['status'] == True:
                args['cart_status'] = 1
            else:
                args['cart_status'] = 0
            
                
            qry = qry.filter_by( cart_status = args["cart_status"])

        for row in qry.all():
            # collect all data to rows
            rows.append(marshal(row, cart_fields))

        for data in rows:
            data['product'] = self.getProduct(data["product_id"])
            data['buyer'] = self.getUser(data["buyer_id"])
            data['seller'] = self.getUser(data["seller_id"])
            ans['result'].append(data)
        return ans, 200


    @user_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('product_id', type= int, location='json', required= True, help= 'product_id must be integer and exist')
        parser.add_argument('seller_id', type= int, location='json', required=True, help= 'seller_id must be integer and exist')

        identity = get_jwt_identity()

        args = parser.parse_args()

        qry = Carts.query.filter_by(product_id=args['product_id']).first()

        if identity == args["seller_id"]:
            return {"message": "You cannot buy your own product"}, 401

        if qry != None:
            return {"message":"Product has been added"}, 401

        data = Carts(
            buyer_id = identity, 
            product_id = args['product_id'], 
            seller_id= args['seller_id'], 
            cart_status= 0      
        )

        db.session.add(data)
        db.session.commit()

        return {"message": "SUCCESS", "cart": marshal(data, cart_fields)}, 200

    @user_required
    def put(self, id):
        # get identity from token
        # current_user = get_jwt_identity()
        # get data where on id
        data = Carts.query.filter_by(id = id).first()

        # if not have data
        if(data == None): 
            # return not found
            return {'message': 'Data not found !!!'}, 404

        parser = reqparse.RequestParser()
        # parser.add_argument("id", type= int, help= 'id key must be an integer and exist', location= 'json', required= False)
        parser.add_argument("buyer_id", type= int, help= 'buyer_id key must be an integer', location= 'json', required= False)
        parser.add_argument("product_id", type= int, help= 'product_id must be an integer', location= 'json', required= False)
        parser.add_argument("seller_id", type= int, help= 'seller_id must be an integer', location= 'json', required= False)
        parser.add_argument("cart_status", type= bool, help= 'cart_status must be an string', location= 'json', required= False)
        # parser.add_argument("banned_status", type= bool, help= 'banned status must be an string and exist', location= 'json', required= True)
        args = parser.parse_args()

        # update the data
        if args["buyer_id"] != None:
            data.buyer_id= args["buyer_id"]
        if args["product_id"] != None:
            data.product_id= args["product_id"]
        if args["seller_id"] != None:
            data.seller_id= args["seller_id"]
        if args["cart_status"] != None:
            data.cart_status= args["cart_status"]
            if args["cart_status"] == True or args["cart_status"] == "true":
                # update updatedAt field when update data
                data.updated_at = db.func.current_timestamp()
        
        db.session.add(data)
        db.session.commit()

        return {"message": "SUCCESS", "cart": marshal(data, cart_fields)}, 200

    @user_required
    def delete(self, id):
        # get data
        data = Carts.query.filter_by(id = id).first()

        #check if data exist
        if data == None:
            # return not found it nothing data
            return {'message': "Data not found!"}, 404

        db.session.delete(data)
        db.session.commit()
        return {'message': "SUCCESS"}, 200


class AdminCartResources(Resource):

    @admin_required
    def get(self):

        ans = {}
        ans["message"] = "SUCCESS"
        rows = []
        
        qry = Carts.query
        
        for row in qry.all():
            # collect all data to rows
            rows.append(marshal(row, cart_fields))
        
        ans["data"] = rows

        # return all data
        return ans, 200
    
    @admin_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('buyer_id', type= int, location='json', required= True, help= 'buyer_id must be integer and exist')
        parser.add_argument('product_id', type= int, location='json', required= True, help= 'product_id must be integer and exist')
        parser.add_argument('seller_id', type= int, location='json', required=True, help= 'seller_id must be integer and exist')
        parser.add_argument('cart_status', type= bool, location='json', required= True, help= 'cart_status must be boolean and exist')

        args = parser.parse_args()

        data = Carts(
            buyer_id = args['buyer_id'], 
            product_id = args['product_id'], 
            seller_id= args['seller_id'], 
            cart_status= args['cart_status']        
        )

        db.session.add(data)
        db.session.commit()

        return {"message": "SUCCESS", "cart": marshal(data, cart_fields)}, 200

    @admin_required
    def put(self, id):
        # get data where on id
        data = Requests.query.filter_by(id = id).first()

        # if not have data
        if(data == None): 
            # return not found
            return {'message': 'Data not found !!!'}, 404

        parser = reqparse.RequestParser()
        # parser.add_argument("id", type= int, help= 'id key must be an integer and exist', location= 'json', required= False)
        parser.add_argument("buyer_id", type= int, help= 'buyer_id key must be an integer', location= 'json', required= False)
        parser.add_argument("product_id", type= int, help= 'product_id must be an integer', location= 'json', required= False)
        parser.add_argument("seller_id", type= int, help= 'seller_id must be an integer', location= 'json', required= False)
        parser.add_argument("cart_status", type= bool, help= 'request_status must be an string', location= 'json', required= False)
        # parser.add_argument("banned_status", type= bool, help= 'banned status must be an string and exist', location= 'json', required= True)
        args = parser.parse_args()

        # update the data
        if args["buyer_id"] != None:
            data.buyer_id= args["buyer_id"]
        if args["product_id"] != None:
            data.product_id= args["product_id"]
        if args["seller_id"] != None:
            data.seller_id= args["seller_id"]
        if args["cart_status"] != None:
            data.cart_status= args["cart_status"]

        # update updatedAt field when update data
        data.updated_at = db.func.current_timestamp()
        
        db.session.add(data)
        db.session.commit()

        return {"message": "SUCCESS", "cart": marshal(data, cart_fields)}, 200

    @admin_required
    def delete(self, id):
        # get data
        data = Carts.query.filter_by(id = id).first()

        #check if data exist
        if data == None:
            # return not found it nothing data
            return {'message': "Data not found!"}, 404

        db.session.delete(data)
        db.session.commit()
        return {'message': "SUCCESS"}, 200

api.add_resource(ProductResources, '/products', '/products/<int:id>')
api.add_resource(ProductPublicResources, '/public/products', '/public/products/<int:id>')
api.add_resource(RegisterResources, '/users/register')
api.add_resource(LoginResources, '/users/login')
api.add_resource(UserResources, '/users', '/users/<int:id>')
api.add_resource(CategoryResources, '/categories', '/categories/<int:id>')
api.add_resource(ProductAdminResources, '/admin/products/<int:id>')
api.add_resource(CartResources, '/users/cart', '/users/cart/<int:id>')
api.add_resource(AdminCartResources, '/admin/cart','/admin/cart/<int:id>')

@jwt.expired_token_loader
def exipred_token_message():
    return json.dumps({"message": "The token has expired"}), 401, {'Content-Type': 'application/json'}

@jwt.user_claims_loader
def add_claim_to_access_token(identity):
    data = Users.query.filter_by(id = identity).first()
    return { "type": data.type }


@jwt.unauthorized_loader
def unathorized_message(error_string):
    return json.dumps({'message': error_string}), 401, {'Content-Type': 'application/json'}


if __name__=='__main__':
    try:
        if sys.argv[1]=='db':
            manager.run()
        else:
            app.run(debug=True,host='0.0.0.0',port=8000)
    except IndexError as p:
        app.run(debug=True,host='0.0.0.0',port=8000)
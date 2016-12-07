# mysql --ssl-mode=REQUIRED --tls-version=TLSv1.2 --ssl-ca rds-ca-2015-root.pem --host fogdog-cluster.cluster-cepyx09zrohr.us-west-2.rds.amazonaws.com --user fogdog --password

import os, ssl, subprocess
cafile = os.path.join(os.path.dirname(__file__), "chalicelib", "rds-ca-2015-root.pem")
ssl_ctx = ssl.create_default_context(cafile=cafile)

from chalice import Chalice
from sqlalchemy import create_engine
connect_args = dict(host="fogdog-cluster.cluster-cepyx09zrohr.us-west-2.rds.amazonaws.com",
                    db="fogdog", user="fogdog", password="fogdogfogdog", ssl=ssl_ctx)
engine = create_engine("mysql+pymysql://", connect_args=connect_args, echo=True)
app = Chalice(app_name='fogdog-api')

from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import sessionmaker
Session = sessionmaker(bind=engine)
class User(Base):
     __tablename__ = 'users'
     id = Column(Integer, primary_key=True)
     name = Column(String(64))
     fullname = Column(String(256))
     password = Column(String(256))
     def __repr__(self):
         return "<User(name='%s', fullname='%s', password='%s')>" % (
             self.name, self.fullname, self.password)


@app.route('/')
def index():
    import boto3
    res = None
    engine.connect()
    #session = Session()
    #ed_user = User(name='ed', fullname='Ed Jones', password='edspassword')
    #session.add(ed_user)
    #session.commit()
    #for instance in session.query(User).order_by(User.id):
    #    res = str(instance)
    '''
    try:
        res = Base.metadata.create_all(engine)
    except Exception as e:
        res = e
    '''
    #sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #return {'hello': 'fogdog', 'port': sock.connect_ex(('172.31.8.208', 22))}
    return {'hello': 'fogdog', 'res': str(res), 'nw': str(boto3.client("ec2").describe_network_interfaces())}
#, 'port': socket.gethostbyname(socket.gethostname()), 'res': str(res), 'nw': boto3.client("ec2").describe_network_interfaces()}

@app.route('/load_gene_abun_dataset')
def load_gene_abun_dataset():
    return {}

@app.route('/load_metabolite_abun_dataset')
def load_metabolite_abun_dataset():
    return {}

@app.route('/load_otu_biom_dataset')
def load_otu_biom_dataset():
    return {}

@app.route('/load_phylogenetic_tree')
def load_phylogenetic_tree():
    return {}


# The view function above will return {"hello": "world"}
# whenver you make an HTTP GET request to '/'.
#
# Here are a few more examples:
#
# @app.route('/hello/{name}')
# def hello_name(name):
#    # '/hello/james' -> {"hello": "james"}
#    return {'hello': name}
#
# @app.route('/users', methods=['POST'])
# def create_user():
#     # This is the JSON body the user sent in their POST request.
#     user_as_json = app.json_body
#     # Suppose we had some 'db' object that we used to
#     # read/write from our database.
#     # user_id = db.create_user(user_as_json)
#     return {'user_id': user_id}
#
# See the README documentation for more examples.
#

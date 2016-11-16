import socket
if socket.gethostname().startswith("serenity"):
    import boto3, botocore, chalice.awsclient, chalice.deployer
    class VPCLambdaClient(chalice.awsclient.TypedAWSClient):
        def create_function(self, function_name, role_arn, zip_contents):
            from aegea.util.aws import ensure_vpc, ensure_subnet, ensure_security_group
            # type: (str, str, str) -> str
            vpc = ensure_vpc()
            kwargs = {
                'FunctionName': function_name,
                'Runtime': 'python2.7',
                'Code': {'ZipFile': zip_contents},
                'Handler': 'app.app',
                'Role': role_arn,
                'Timeout': 60,
                'VpcConfig': {
                    'SubnetIds': [ensure_subnet(vpc).id],
                    'SecurityGroupIds': [ensure_security_group("aegea.launch", vpc).id]
                }
            }
            client = self._client('lambda')
            attempts = 0
            while True:
                try:
                    response = client.create_function(**kwargs)
                except botocore.exceptions.ClientError as e:
                    code = e.response['Error'].get('Code')
                    if code == 'InvalidParameterValueException':
                        # We're assuming that if we receive an
                        # InvalidParameterValueException, it's because
                        # the role we just created can't be used by
                        # Lambda.
                        self._sleep(self.DELAY_TIME)
                        attempts += 1
                        if attempts >= self.LAMBDA_CREATE_ATTEMPTS:
                            raise
                        continue
                    raise
                return response['FunctionArn']

    chalice.awsclient.TypedAWSClient = VPCLambdaClient
    chalice.deployer.TypedAWSClient = VPCLambdaClient

from chalice import Chalice

app = Chalice(app_name='fogdog-api')


@app.route('/')
def index():
    return {'hello': 'world'}


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

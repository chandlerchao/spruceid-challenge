# SpruceID Code Sample

## Description
This sample project is composed of a client and service used to demonstrate message signing with private keys.

### Keys
Ed25519 was chosen for the key format as it is robust and faster than RSA. 

The keys are stored in the .ssh directory of the repo. A copy of the public key has been inserted in to the api project for ease of reference within the api.

### Python Client
The client is a Python 3.13 script. It will send a nonce and timestamp in the payload to help prevent replay requests.

### .Net API
The Api is a .Net 8.0 ASP.net CORE project. It consists of two projects: SpruiceID-api and SpruceIDapiTestProject. The former is the API and the latter is a suite of unit tests.

Used nonces are kept in a text file. This is understanbly not a production strategy, but should be sufficient for this sample project. The API ensures that nonces are only good for 5 minutes

## Setup
### Python Client
They Python client can be setup by using [miniconda](https://www.anaconda.com/download/success).

Once installed, open an Anaconda prompt and create a conda enviornment with the packages needed to run the project.

`conda create -n spruceid python=3.13 -c conda-forge pynacl cryptography requests typing-extensions`

Activate the conda environment just created.

`conda activate spruceid`

### .Net API
The easiest way to setup and run the API is to open the .sln file in Visual Studio (v2022 preferably).

After opening the solution, right click on the solution name and choose *Restore Nuget Packages*.

## Running
### .Net API
With the SpruceID-api set as your default project, simply press Ctrl-F5 to start the API. It may ask you to approve the self signed certificate. It should open a browser window with the Swagger page describing the endpoints.

### Python Client
You may need to edit the client/main.py to update the URL for the API. You can extract that from the Swagger page URL above.

In the Anaconda prompt that was opened above, navigate into the client directory.

`cd client`

Execute the main.py python script.

`python main.py`

The script will prompt you for the path to the private key .pem file. By default it will reference `.ssh/private.pem`, so you can just press return to accept it.

The script will show a warning about the self-signed certificate. This can be ignored.

It will output the status code of the request and a corresponding message returned from the API.
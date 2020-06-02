from srp import Client, Server

if __name__ == '__main__':
    client = Client()
    serv = Server()

    I = 'alice'
    P = 'password123'
    print(f'I = {I}, P = {P}')
    
    print('Client: computes verifier')
    salt, verifier = client.compute_verifier(I, P)
    print(f'Salt is: {salt}')
    print(f'Verifier is: {verifier}')

    print('Client->I, s, v->Server')
    print('Client: computes private and public values')
    A = client.compute_client_values()
    print(f'CLient A: {A}')

    print('Client->A->Server')
    print('Server: computes private and public values')
    B = serv.compute_server_values(I, verifier)
    print(f'Server B: {B}')

    print('Server->B->CLient')
    print('Client: computes premaster secret and session key')
    client.compute_premaster_secret(salt, B)
    M = client.compute_session_key(salt, B)

    print('Server: computes premaster secret and session key')
    serv.compute_premaster_secret(I, salt, verifier, A)
    serv.compute_session_key(I, salt, A)

    print(f'Client evidence message: {M}')
    print(f'Server evidence message: {serv.M}')

    print('Client->M->Server')
    print('Server: verifies session')
    hashed_M = serv.verify_session(M)
    print(f'Server hashed_M: {hashed_M}')

    print('Server->hashed_M->Client')
    print('Client: verifies session')
    hashed_M = client.verify_session(hashed_M)
    print(f'Client hashed_M: {hashed_M}')

    print(f'Client session key: {client.session_key}')
    print(f'Server session key: {serv.session_key}')

    assert client.authenticated
    assert serv.authenticated

    print('Success')

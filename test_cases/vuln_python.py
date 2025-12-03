import os

def process_request(request):
    user_input = request.GET['cmd']
    # VULNERABLE: Direct execution of user input
    os.system("ping " + user_input)

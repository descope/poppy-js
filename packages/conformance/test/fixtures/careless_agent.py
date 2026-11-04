"""A deliberately careless Personal Agent in Python, using only the standard library.

It trusts any Company, sends a guessed token instead of a Session JWT, and follows redirects with it.
The conformance suite should fail it. It shows the harness works for agents outside TypeScript:
urllib reaches the test Company through HTTPS_PROXY and trusts the CA in SSL_CERT_FILE.
"""
import json
import os
import ssl
import urllib.request

context = json.loads(os.environ["POPPY_CONFORMANCE_CONTEXT"])
tls = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=tls))

for step in context["steps"]:
    try:
        if step["action"] == "discover":
            opener.open(step["website"] + "/.well-known/poppy.json").read()
        elif step["action"] == "request":
            request = urllib.request.Request(step["url"], method=step.get("method", "GET"))
            request.add_header("Authorization", "Bearer guessed")
            opener.open(request).read()
        else:
            raise RuntimeError("not implemented")
    except Exception as error:  # Keep going, as the contract asks.
        print(json.dumps({"step": step["action"], "error": str(error)}))

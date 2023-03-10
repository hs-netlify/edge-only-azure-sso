const createForm = (details) => {
  let formBody = [];
  for (const property in details) {
    const encodedKey = encodeURIComponent(property);
    const encodedValue = encodeURIComponent(details[property]);
    formBody.push(encodedKey + "=" + encodedValue);
  }
  formBody = formBody.join("&");
  return formBody;
};

const getToken = async (code, clientId, secret, url, state) => {
  const config = {
    grant_type: "authorization_code",
    code: code,
    client_id: clientId,
    client_secret: secret,
    redirect_uri: url,
    state,
  };
  const form = createForm(config);

  const res = await fetch(
    "https://login.microsoftonline.com/7c33e7e3cfed48239c3cee38f4235944/oauth2/v2.0/token",
    {
      method: "POST",
      headers: {
        "Content-type": "application/x-www-form-urlencoded",
      },
      body: form,
    }
  );

  const data = await res.json();
  return data.access_token;
};

const ssoAuth = async (request, context) => {
  const {
    AZURE_AD_CLIENT_ID: clientId,
    AZURE_AD_TENANT_ID: tenantId,
    AZURE_AD_SECRET: secret,
  } = Deno.env.toObject();

  if (clientId && tenantId && secret) {
    // const authToken = context.cookies.get("AAD_Token");
    const url = new URL(request.url);
    const path = url.pathname;
    const params = new URLSearchParams(url.search);
    const code = params.get("code");
    const state = params.get("state");

    const redirectUri = url.origin;
    const originAppUrl = params.get("origin");

    const authRedirect = () => {
      return Response.redirect(
        `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize?client_id=${clientId}&response_type=code&redirect_uri=${encodeURIComponent(
          redirectUri
        )}&response_mode=query&scope=https://graph.microsoft.com/openid&state=${originAppUrl}`
      );
    };

    if (code) {
      console.log("state here", state);
      const access_token = await getToken(code, clientId, secret, url.origin);
      if (access_token) {
        const res = new Response(null, {
          status: 302,
        });
        res.headers.set("Location", `${state}?aadToken=${access_token}`);

        return res;
      } else {
        return authRedirect();
      }
    } else {
      return authRedirect();
    }
  } else {
    console.log(
      "ERROR - ENV Vars not set: AZURE_AD_CLIENT_ID , AZURE_AD_TENANT_ID, AZURE_AD_SECRET"
    );
    return;
  }
};

export default ssoAuth;

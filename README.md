# JWT authentication in an Angular application with a Go backend

_Originally published on [my blog](http://www.nikola-breznjak.com/blog/go/jwt-authentication-angular-application-go-backend/)._

## TL;DR
In this tutorial, I'm going to show you how to build a simple web app that handles authentication using JWT. The frontend will be written in Angular 5, and the backend will be in Go. I'll cover some theory concepts along the way as well.

You can check out the final source code [on Github]().

## JWT
JWT stands for `JSON Web Token`, and it is an encoded string that, for example,  looks like this:

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYTFiMmMzIiwidXNlcm5hbWUiOiJuaWtvbGEifQ==.mKIuU0V0Bo99JU5XbeMe6g-Hrd3ZxJRlmdHFrEkz0Wk`

If you split this string by `.`, you'll get three separate strings:

+ **header**  - contains encoded information about the token
+ **payload** - contains encoded data that is being transmitted between two parties
+ **verification signature** - used to verify that the data has not been changed

The official website says this about JWTs:

> JSON Web Tokens are an open, industry standard RFC 7519 method for representing claims securely between two parties.

If you're like 

![](https://i.imgur.com/hzZHo9S.jpg)

then I don't blame you. So let's define this in a bit more detail.

JSON Web Tokens are a way to communicate information between two parties securely. A `claim` is some data that is sent along with the token, like `user_id`.

**Secure communication** in this context refers to the fact that we can be certain that the information **has not been tampered** with, but it does not mean that it is hidden from a potential attacker. Actually, a potential attacker could read what is in JWT (so please **don't send any passwords** as claims), but he wouldn't be able to modify it and send it back in that form.

Based on the premise that a JWT can't be tampered with, it is very useful for **authentication**. We can give a user a JWT that contains their `userid`, which can be stored locally and used to verify that requests are coming from an authenticated user.

JWTs are short, so you can easily send them as a POST parameter, HTTP header, or add it as a query string to a URL. You can store them in local storage and then send them with every request to the server, making sure the user is authorized.

It seems that a lot of people like and use them. However, I must note that [a lot](https://news.ycombinator.com/item?id=16157002) of security researchers [frown upon this practice](https://www.rdegges.com/2018/please-stop-using-local-storage/).

## Learn by doing
It's not necessary to know the intricate details of how JWTs work, to be able to use them, but it can sometimes give you this great feeling of awesomeness when you go an extra mile.

So, with that spirit in mind, we're going to create our own JSON Web Token now 💪

### Payload
For example, say that I want to send the following data securely to someone:

```
{
    "user_id": "a1b2c3",
    "username": "nikola"
}
```

This is my `payload`. To add it to our JWT, we first need to `base64` encode it. You can do this easily with JavaScript inside your browser's developer tools (Console window) by using the `btoa` function:

```
btoa(JSON.stringify({
    "user_id": "a1b2c3",
    "username": "nikola"
}));
```

Or, with the ever so slightly popular Go, you would do it like this:

```
package main

import (
    "encoding/base64"
    "fmt"
)

func main() {
    data := `{"user_id":"a1b2c3","username":"nikola"}`
    uEnc := base64.URLEncoding.EncodeToString([]byte(data))
    fmt.Println(uEnc)
}
```
 
which then gives you: 
`eyJ1c2VyX2lkIjoiYTFiMmMzIiwidXNlcm5hbWUiOiJuaWtvbGEifQ==`

> ⚠️ In the JavaScript example we had to use the `JSON.stringify` function first, as otherwise the resulting decoded string would just be `[object Object]`.

We can decode the base64 encoded string by using the `atob` function in JavaScript:

```
atob('eyJ1c2VyX2lkIjoiYTFiMmMzIiwidXNlcm5hbWUiOiJuaWtvbGEifQ==')
```

or in Go:

```
uDec, _ := base64.URLEncoding.DecodeString("eyJ1c2VyX2lkIjoiYTFiMmMzIiwidXNlcm5hbWUiOiJuaWtvbGEifQ==")
```

The result, in both cases, is `{"user_id":"a1b2c3","username":"nikola"}`

### Header
Next, we need to encode the header:

```
{
    "alg": "HS256",
    "typ": "JWT"
}
```

In JWT, the header actually comes before the payload. In the header, we are specifying that we created a JWT and that we used a certain hashing algorithm `HS256`. This particular algorithm will allow us to use a secret password. You could use the `RSA SHA256` algorithm to use a private & public key pair instead. [Here's](https://blog.angular-university.io/angular-jwt/) a good tutorial on the different hashing algorithms used in JWTs.

The header, base64 encoded, looks like this: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`.

### Verification signature
As the last step, we need to create the verification signature. We do this by joining the encoded header and payload string, separating them with `.`. After that, we need to apply the `HS256` algorithm along with the secret password that is only known to the sender.

Our encoded header and payload look like this:

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYTFiMmMzIiwidXNlcm5hbWUiOiJuaWtvbGEifQ==`

We're going to use `42isTheAnswer` as our password.

We don't have this hashing function available in the browser, so we need to use Node to do it. First, install `base64url` by running: `npm install base64url`. If you're new to Node, I recommend [this tutorial](https://hackhands.com/how-to-get-started-on-the-mean-stack/).

Create a new JavaScript file with the following content:

```
var base64url = require('base64url');
 
var crypto    = require('crypto');
var message     = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYTFiMmMzIiwidXNlcm5hbWUiOiJuaWtvbGEifQ==';
var key       = '42isTheAnswer';
var algorithm = 'sha256';
var hash, hmac;
 
hmac = crypto.createHmac(algorithm, key);
hmac.setEncoding('base64');
hmac.write(message);
hmac.end();
hash = hmac.read();
 
var final = base64url.fromBase64(hash);
console.log(final);
```

Or, in Go, you would use:

```
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
)

func main() {
    message := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYTFiMmMzIiwidXNlcm5hbWUiOiJuaWtvbGEifQ=="
    sKey := "42isTheAnswer"

    key := []byte(sKey)
    h := hmac.New(sha256.New, key)
    h.Write([]byte(message))
    b := base64.URLEncoding.EncodeToString(h.Sum(nil))
    fmt.Println(string(a))
}
```

After you execute any of the scripts above, you should get this string:

`mKIuU0V0Bo99JU5XbeMe6g-Hrd3ZxJRlmdHFrEkz0Wk`

Now we add this string to the token from before (also separated by `.`) and we get:

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYTFiMmMzIiwidXNlcm5hbWUiOiJuaWtvbGEifQ==.mKIuU0V0Bo99JU5XbeMe6g-Hrd3ZxJRlmdHFrEkz0Wk`

We can test this JWT on [jwt.io](https://jwt.io/):

![](https://i.imgur.com/OOsBnYy.png)

## Security
Our `payload` and `header` were just base64 encoded, which can just as easily be base64 decoded. So, how exactly is this secure then?

The important point is that it **can't be changed**, since the verification signature is built using the header and the payload data, if either of those change, we won't be able to verify the signature – so if somebody tampers with the JWT, we will know.

Since the payload data has been changed, the verification signature will no longer match, and there's no way to forge the signature unless you know the secret that was used to hash it. When this JWT hits the server, it will know that it has been tampered with.

## General remarks
If JWTs are used for Authentication, they will contain at least a user ID and an `expiration timestamp`.
This type of token is known as a `Bearer Token`. It identifies the user that owns it and defines a user session.

A `Bearer Token` is a signed temporary replacement for the username/password combination. The very first step for implementing JWT-based authentication is to issue a Bearer Token and give it to the user through the process of logging in.

The key property of JWTs is that to confirm if they are valid we only need to look at the token itself.

## Demo apps
We're going to build a simple full-stack app that will have a:

+ landing page
+ login page
+ members page
+ backend for authentication

Here's how the authentication with JWTs works:

![](https://i.imgur.com/hthWzSx.png)

+ user submits the username and password to the server via the login page
+ server validates the sent data and creates a JWT token with a payload containing the user's id and an expiration timestamp
+ server signs the Header and Payload with a secret password and sends it back to the user's browser
+ browser takes the signed JWT and starts sending it with each HTTP request back to the server
+ signed JWT acts as a temporary user credential, that replaces the permanent credential (username and password)

Here's what the server does upon receiving the JWT token:

+ the server checks the JWT signature and confirms that it's valid
+ the Payload identifies a particular user via a user id
+ only the server has the secret password, and the server only gives out tokens to users that submit the correct password. Therefore, the server can be certain that this token was indeed given to this particular user by the server
+ the server proceeds with processing the HTTP request with this user's credentials

### Angular CLI with Bulma
[Angular CLI](https://cli.angular.io/) is an awesome tool for [Angular](https://angular.io/), and [Bulma](https://bulma.io/) is a simple CSS framework that's just a pure joy to work with.

Let's start by generating a new project with Angular CLI (install it, in case you don't have it already):

`ng new jwt-auth`

After this process is finished, run `ng serve` inside the `jwt-auth` folder, and you'll have an app running at [http://localhost:4200/](http://localhost:4200/):

![](https://i.imgur.com/WtR7ukv.png)

#### Adding Bulma

Add this in the `index.html` file:

```
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bulma/0.6.2/css/bulma.min.css">
  <script defer src="https://use.fontawesome.com/releases/v5.0.0/js/all.js"></script>
```

Update `app.component.html` to:

```
<nav class="navbar">
  <div class="container">
    <div class="navbar-brand">
      <a class="navbar-item">
        JWT Angular Login
      </a>
    </div>

    <div id="navbarMenuHeroA" class="navbar-menu">
      <div class="navbar-end">
        <a class="navbar-item">
          Home
        </a>
        <a class="navbar-item">
          Login
        </a>
        <a class="navbar-item">
          Members
        </a>
        <a class="navbar-item">
          Logout
        </a>
      </div>
    </div>
  </div>
</nav>

<router-outlet></router-outlet>

<footer class="footer">
  <div class="container has-text-centered">
    <div class="content">
      From Croatia with ❤️
    </div>
  </div>
</footer>
```

If you take a look at the page now, you'll see:

![](https://i.imgur.com/jiXVEYT.png)

So, we have a header with links and a footer with simple text.

The `<router-outlet></router-outlet>` element will be used to serve other pages.

Now, let's create three new components using Angular CLI:

```
ng g component home
ng g component login
ng g component members
```

One reason why Angular CLI is useful is that by generating the component, it creates 3 files for us and imports the component in the `app.module.ts` file:

```
create src/app/members/members.component.css (0 bytes)
create src/app/members/members.component.html (26 bytes)
create src/app/members/members.component.spec.ts (635 bytes)
create src/app/members/members.component.ts (273 bytes)
update src/app/app.module.ts (1124 bytes)
```

Now, let's wire up the routes in `app.module.ts`:

```
const routes = [
    { path: 'login', component: LoginComponent },
    { path: 'members', component: MembersComponent },
    { path: '', component: HomeComponent },
    { path: '**', redirectTo: '' }
];

...
imports: [
    BrowserModule,
    RouterModule.forRoot(routes)
],
```

Set the links in the `app.component.html` using `routerLink` like this:

```
<a class="navbar-item" [routerLink]="['']">Home</a>
<a class="navbar-item" [routerLink]="['/login']">Login</a>
<a class="navbar-item" [routerLink]="['/members']">Members</a>
```

If all is fine, you should see this in your browser:

![](https://i.imgur.com/rkIbHca.gif)

#### Login
Replace the contents of the `login.component.html` with:

```
<section class="hero">
  <div class="hero-body has-text-centered">
    <form [formGroup]="form">
      <div class="columns">
        <div class="column"></div>

        <div class="column is-3">
          <div class="field">
            <label class="label is-pulled-left">Email</label>
            <div class="control">
              <input class="input" type="text" placeholder="john@gmail.com" formControlName="email" name="email">
            </div>
          </div>
        </div>

        <div class="column"></div>
      </div>

      <div class="columns">
        <div class="column"></div>

        <div class="column is-3">
          <div class="field">
            <label class="label is-pulled-left">Password:</label>
            <div class="control">
              <input class="input" type="password" formControlName="password" name="password">
            </div>

            <br>
            <br>
            <a class="button is-primary is-medium is-fullwidth" (click)='login()'>Login</a>
          </div>
        </div>

        <div class="column"></div>
      </div>
    </form>
  </div>
</section>
```

and add `login.component.ts` with:

```
import { Component, OnInit } from '@angular/core';
import { FormGroup, FormBuilder, Validators, FormsModule, ReactiveFormsModule } from '@angular/forms';

@Component({
    selector: 'app-login',
    templateUrl: './login.component.html',
    styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
    form: FormGroup;

    constructor(private fb: FormBuilder) {
        this.form = this.fb.group({
            email: ['', Validators.required],
            password: ['', Validators.required]
        });
    }

    ngOnInit() {
    }

    login() {
        console.log('Clicked the Login button');
    }
}
```

You may notice that we used a bunch of imports from `@angular/forms`, so we also need to add it in `app.module.ts` in the `imports` array:

```
...
imports: [
    BrowserModule,
    FormsModule,
    ReactiveFormsModule,
    RouterModule.forRoot(routes)
],
...
```

Before we go to the actual authentication section, let's just fix the Home and Members area slightly.

#### Home and Members
Update the HTML files to the following content:

`home.component.html`:

```
<section class="hero" id="hero">
  <div class="hero-head"></div>
  <div class="hero-body">
    <div class="container has-text-centered">
      <h1 class="is-1 title">
        Welcome to JWT Angular Auth!
      </h1>
    </div>
  </div>
</section>
```

`members.component.html`:

```
<section class="hero" id="hero">
  <div class="hero-head"></div>
  <div class="hero-body">
    <div class="container has-text-centered">
      <h1 class="is-1 title">
        Members area
      </h1>
    </div>
  </div>
</section>
```

### Go
Our backend is written in Golang, and it looks like this:

```
package main

import (
    "encoding/json"
    "errors"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "strings"
    "time"

    jwt "github.com/dgrijalva/jwt-go"
    "github.com/rs/cors"
)

const (
    PORT   = "1337"
    SECRET = "42isTheAnswer"
)

type JWTData struct {
    // Standard claims are the standard jwt claims from the IETF standard
    // https://tools.ietf.org/html/rfc7519
    jwt.StandardClaims
    CustomClaims map[string]string `json:"custom,omitempty"`
}

type Account struct {
    Email    string  `json:"email"`
    Balance  float64 `json:"balance"`
    Currency string  `json:"currency"`
}

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", hello)
    mux.HandleFunc("/login", login)
    mux.HandleFunc("/account", account)

    handler := cors.Default().Handler(mux)

    log.Println("Listening for connections on port: ", PORT)
    log.Fatal(http.ListenAndServe(":"+PORT, handler))
}

func hello(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello from Go!")
}

func login(w http.ResponseWriter, r *http.Request) {
    body, err := ioutil.ReadAll(r.Body)
    if err != nil {
        log.Println(err)
        http.Error(w, "Login failed!", http.StatusUnauthorized)
    }

    var userData map[string]string
    json.Unmarshal(body, &userData)

    // Demo - in real case scenario you'd check this against your database
    if userData["email"] == "admin@gmail.com" && userData["password"] == "admin123" {
        claims := JWTData{
            StandardClaims: jwt.StandardClaims{
                ExpiresAt: time.Now().Add(time.Hour).Unix(),
            },

            CustomClaims: map[string]string{
                "userid": "u1",
            },
        }

        token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
        tokenString, err := token.SignedString([]byte(SECRET))
        if err != nil {
            log.Println(err)
            http.Error(w, "Login failed!", http.StatusUnauthorized)
        }

        json, err := json.Marshal(struct {
            Token string `json:"token"`
        }{
            tokenString,
        })

        if err != nil {
            log.Println(err)
            http.Error(w, "Login failed!", http.StatusUnauthorized)
        }

        w.Write(json)
    } else {
        http.Error(w, "Login failed!", http.StatusUnauthorized)
    }
}

func account(w http.ResponseWriter, r *http.Request) {
    authToken := r.Header.Get("Authorization")
    authArr := strings.Split(authToken, " ")

    if len(authArr) != 2 {
        log.Println("Authentication header is invalid: " + authToken)
        http.Error(w, "Request failed!", http.StatusUnauthorized)
    }

    jwtToken := authArr[1]

    claims, err := jwt.ParseWithClaims(jwtToken, &JWTData{}, func(token *jwt.Token) (interface{}, error) {
        if jwt.SigningMethodHS256 != token.Method {
            return nil, errors.New("Invalid signing algorithm")
        }
        return []byte(SECRET), nil
    })

    if err != nil {
        log.Println(err)
        http.Error(w, "Request failed!", http.StatusUnauthorized)
    }

    data := claims.Claims.(*JWTData)

    userID := data.CustomClaims["userid"]

    // fetch some data based on the userID and then send that data back to the user in JSON format
    jsonData, err := getAccountData(userID)
    if err != nil {
        log.Println(err)
        http.Error(w, "Request failed!", http.StatusUnauthorized)
    }

    w.Write(jsonData)
}

func getAccountData(userID string) ([]byte, error) {
    output := Account{"nikola.breznjak@gmail.com", 3.14, "BTC"}
    json, err := json.Marshal(output)
    if err != nil {
        return nil, err
    }

    return json, nil
}
```

> ⚠️ I'm not a Go expert (yet), so this code would be written way more idiomatic by someone who's using the language longer. But, when confronted with such thoughts yourself, remember this: "Perfect is the enemy of good", and it's way better to learn by doing and getting stuff 'out there' and getting feedback, than to 'wait x months until you master a language'.

So, here goes my best attempt at explaining what the code does, from top to bottom:

#### package
```
package main
```

First, we have the `package` statement. Every Go program must have a `main` package.

#### imports
```
import (
    "encoding/json"
    "errors"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "strings"
    "time"

    jwt "github.com/dgrijalva/jwt-go"
    "github.com/rs/cors"
)
```

Then we have the imports. All of the imports, except for jwt and cors are from the standard Go library. If you're using an editor like VS Code, or an IDE like GoLand, then these imports are added automatically as you save your code.

One thing I love about Go is the auto code format, so finally, some language where there will be no debate about whether the brackets in `if`s go on the same line or in the next. Consistency FTW!

#### constants
```
const (
    PORT   = "1337"
    SECRET = "42isTheAnswer"
)
```

Then we have two constants: `PORT` and `SECRET`. It is **not** a practice in Go to have all [uppercase letters for constants](https://stackoverflow.com/questions/22688906/go-naming-conventions-for-const), but I'm blindly sticking to that habit it seems.

#### structs
```
type JWTData struct {
    // Standard claims are the standard jwt claims from the IETF standard
    // https://tools.ietf.org/html/rfc7519
    jwt.StandardClaims
    CustomClaims map[string]string `json:"custom,omitempty"`
}

type Account struct {
    Email    string  `json:"email"`
    Balance  float64 `json:"balance"`
    Currency string  `json:"currency"`
}
```

Next, we have two structs: `JWTData` and `Account`. The `JWTData` struct, along with some standard fields (claims) has an additional `CustomClaims` map, that can hold key-value pairs of type `string`. We will use this data type to add our own custom claims (`userid`).

The `Account` struct is used as an example structure for responding to the logged in user once he's logged in and comes to the Members page. It contains the `Email`, `Balance` and `Currency` fields.

#### main
```
func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", hello)
    mux.HandleFunc("/login", login)
    mux.HandleFunc("/account", account)

    handler := cors.Default().Handler(mux)

    log.Println("Listening for connections on port: ", PORT)
    log.Fatal(http.ListenAndServe(":"+PORT, handler))
}
```

In the `main` function we 'register' the handlers for our API. If we presume that this Go program would be running on a domain `http://api.boringcompany.com`, then the request to that URL would be handled by the `hello` function that we'll show below. If the request is sent to the `http://api.boringcompany.com/login` URL, it would be handled by the `login` function that we'll show below, etc. Finally, we print the message via the `log` and start the server with the `http.ListenAndServe` function.

The CORS handler is necessary only when developing locally. If you'll do that, then I also recommend the CORS plugin for the browser you're using ([here is the one](https://chrome.google.com/webstore/detail/allow-control-allow-origi/nlfbmbojpeacfghkpbjhddihlkkiljbi?hl=en) that I use for Chrome).

#### hello handler
```
func hello(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello from Go!")
}
```

This is a simple function that outputs `Hello from Go!` back to the user when he hits our main API URL.

#### login handler
```
func login(w http.ResponseWriter, r *http.Request) {
    body, err := ioutil.ReadAll(r.Body)
    if err != nil {
        log.Println(err)
        http.Error(w, "Login failed!", http.StatusUnauthorized)
    }

    var userData map[string]string
    json.Unmarshal(body, &userData)

    // Demo - in real case scenario you'd check this against your database
    if userData["email"] == "admin@gmail.com" && userData["password"] == "admin123" {
        claims := JWTData{
            StandardClaims: jwt.StandardClaims{
                ExpiresAt: time.Now().Add(time.Hour).Unix(),
            },

            CustomClaims: map[string]string{
                "userid": "u1",
            },
        }

        token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
        tokenString, err := token.SignedString([]byte(SECRET))
        if err != nil {
            log.Println(err)
            http.Error(w, "Login failed!", http.StatusUnauthorized)
        }

        json, err := json.Marshal(struct {
            Token string `json:"token"`
        }{
            tokenString,
        })

        if err != nil {
            log.Println(err)
            http.Error(w, "Login failed!", http.StatusUnauthorized)
        }

        w.Write(json)
    } else {
        http.Error(w, "Login failed!", http.StatusUnauthorized)
    }
}
```

In the `login` function we first read the body of the request and parse out the `email` and `password` parameters. We then check this email/password combination and make sure it's correct. Of course, for demo purposes it was done like that in the code; in real case scenario, you'd check this against your database most probably.

If the user credentials are correct, we prepare the claims where we use the standard `ExpiresAt` claim, and also we add our own custom claim of `userid` with the value `u1`.

Next, we use the `jwt.NewWithClaims` function to sign the header and the payload with the `HS256` hashing algorithm and we use the `SECRET` as a key for that. Finally, we then return this token to the user in JSON format.

Otherwise, if any errors happen, we send back the unauthorized status with a failure message.

#### account handler
```
func account(w http.ResponseWriter, r *http.Request) {
    authToken := r.Header.Get("Authorization")
    authArr := strings.Split(authToken, " ")

    if len(authArr) != 2 {
        log.Println("Authentication header is invalid: " + authToken)
        http.Error(w, "Request failed!", http.StatusUnauthorized)
    }

    jwtToken := authArr[1]

    claims, err := jwt.ParseWithClaims(jwtToken, &JWTData{}, func(token *jwt.Token) (interface{}, error) {
        if jwt.SigningMethodHS256 != token.Method {
            return nil, errors.New("Invalid signing algorithm")
        }
        return []byte(SECRET), nil
    })

    if err != nil {
        log.Println(err)
        http.Error(w, "Request failed!", http.StatusUnauthorized)
    }

    data := claims.Claims.(*JWTData)

    userID := data.CustomClaims["userid"]

    // fetch some data based on the userID and then send that data back to the user in JSON format
    jsonData, err := getAccountData(userID)
    if err != nil {
        log.Println(err)
        http.Error(w, "Request failed!", http.StatusUnauthorized)
    }

    w.Write(jsonData)
}

func getAccountData(userID string) ([]byte, error) {
    output := Account{"nikola.breznjak@gmail.com", 3.14, "BTC"}
    json, err := json.Marshal(output)
    if err != nil {
        return nil, err
    }

    return json, nil
}
```

In the `account` function we first read the `Authorization` header and take out the token. Then we make sure the token is valid and has not been tampered with, and we parse out the claims by using the `jwt.ParseWithClaims` function.

With the `userID` claim we fetch some data (using the `getAccountData` function) and then send that data back to the user in the JSON format.

#### Running the Go app
You can run this app locally on your computer with `go run main.go`. Of course, you need to have Go installed. You can check how to do that in [this tutorial](https://golang.org/doc/install).

### Finishing up the Angular frontend
Now let's switch back to our Angular project and make actual requests to our API.

#### Auth service
Using Angular CLI, execute the following command in your terminal:

```
ng g service auth 
```

This now created two files for us:

```
create src/app/auth.service.spec.ts (362 bytes)
create src/app/auth.service.ts (110 bytes)
```

Copy the following code to the `auth.service.ts` file:

```
import { Injectable } from '@angular/core';
import { RequestOptions, Response } from '@angular/http';

import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Router } from '@angular/router';

@Injectable()
export class AuthService {

    API_URL = 'http://localhost:1337';
    TOKEN_KEY = 'token';

    constructor(private http: HttpClient, private router: Router) { }

    get token() {
        return localStorage.getItem(this.TOKEN_KEY);
    }

    get isAuthenticated() {
        return !!localStorage.getItem(this.TOKEN_KEY);
    }

    logout() {
        localStorage.removeItem(this.TOKEN_KEY);
        this.router.navigateByUrl('/');
    }

    login(email: string, pass: string) {
        const headers = {
            headers: new HttpHeaders({ 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' })
        };

        const data = {
            email: email,
            password: pass
        };

        this.http.post(this.API_URL + '/login', data, headers).subscribe(
            (res: any) => {
                localStorage.setItem(this.TOKEN_KEY, res.token);

                this.router.navigateByUrl('/members');
            }
        );
    }

    getAccount() {
        return this.http.get(this.API_URL + '/account');
    }
}
```

`AuthService` consists of these functions:

+ `login` - we send the email/password that the user enters to the server and upon success, we store the token in local storage. _Please note the warning that I gave in the theory part of this tutorial._
+ `logout` - we delete the token from local storage and redirect the user to the landing page
+ `token` - returns the token from local storage
+ `isAuthenticated` - returns true/false if the token exists in the local storage
+ `getAccount` - requests the user data and returns a promise

#### login component
```
import { Component, OnInit } from '@angular/core';
import { FormGroup, FormBuilder, Validators, FormsModule, ReactiveFormsModule } from '@angular/forms';
import { AuthService } from '../auth.service';

@Component({
    selector: 'app-login',
    templateUrl: './login.component.html',
    styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
    form: FormGroup;

    constructor(private fb: FormBuilder, private authService: AuthService) {
        this.form = this.fb.group({
            email: ['', Validators.required],
            password: ['', Validators.required]
        });
    }

    ngOnInit() {
    }

    login() {
        const val = this.form.value;

        if (val.email && val.password) {
            this.authService.login(val.email, val.password);
        }
    }
}
```

The most important part is the login function that calls the `AuthService` login function passing it `email` and `password`. We use the `FormBuilder` in Angular to access form fields that in the HTML code look like this:

```
<section class="hero">
  <div class="hero-body has-text-centered">
    <form [formGroup]="form">
      <div class="columns">
        <div class="column"></div>

        <div class="column is-3">
          <div class="field">
            <label class="label is-pulled-left">Email</label>
            <div class="control">
              <input class="input" type="text" placeholder="john@gmail.com" formControlName="email" name="email">
            </div>
          </div>
        </div>

        <div class="column"></div>
      </div>

      <div class="columns">
        <div class="column"></div>

        <div class="column is-3">
          <div class="field">
            <label class="label is-pulled-left">Password:</label>
            <div class="control">
              <input class="input" type="password" formControlName="password" name="password">
            </div>

            <br>
            <br>
            <a class="button is-primary is-medium is-fullwidth" (click)='login()'>Login</a>
          </div>
        </div>

        <div class="column"></div>
      </div>
    </form>
  </div>
</section>
```

Notice `<form [formGroup]="form">` and `formControlName="email"`. In Angular we register the click handler like this: `(click)='login()'`.

#### members component
Members component is pretty simple:

```
<section class="hero" id="hero">
  <div class="hero-head"></div>
  <div class="hero-body">
    <div class="container has-text-centered">
      <h1 class="is-1 title">
        Members area
      </h1>

      <p>Email:
        <b>{{accountData?.email}}</b>
      </p>
      <p>Balance:
        <b>{{accountData?.balance}} {{accountData?.currency}}</b>
      </p>
    </div>
  </div>
</section>
```

We use it to show some data that we'll get from the API. Very important part is the use of `?` - this instructs Angular to not throw an error while it's rendering the template in case the data doesn't yet exist (as it will be the case since we're fetching this data from an API).

The controller code looks like this:

```
import { Component, OnInit } from '@angular/core';
import { AuthService } from '../auth.service';
import { Router } from '@angular/router';

@Component({
    selector: 'app-members',
    templateUrl: './members.component.html',
    styleUrls: ['./members.component.css']
})
export class MembersComponent implements OnInit {
    accountData: any;
    constructor(private authService: AuthService, private router: Router) { }

    ngOnInit() {
        this.authService.getAccount().subscribe(
            (res: any) => {
                this.accountData = res;
            }, (err: any) => {
                this.router.navigateByUrl('/login');
            }
        );
    }

}
```

When the component loads, we send a request to the API, and upon the success, we save the data in the `accountData` variable that we then use in the template as we saw previously. If an error occurs, we forward the user to the landing page.

#### app.component.html
```
<nav class="navbar">
  <div class="container">
    <div class="navbar-brand">
      <a class="navbar-item">
        JWT Angular Login
      </a>
    </div>

    <div id="navbarMenuHeroA" class="navbar-menu">
      <div class="navbar-end">
        <a class="navbar-item" [routerLink]="['']">
          Home
        </a>
        <a class="navbar-item" [routerLink]="['/login']" *ngIf="!authService.isAuthenticated">
          Login
        </a>
        <a class="navbar-item" [routerLink]="['/members']" *ngIf="authService.isAuthenticated">
          Members
        </a>
        <a class="navbar-item" *ngIf="authService.isAuthenticated" (click)="authService.logout()">
          Logout
        </a>
      </div>
    </div>
  </div>
</nav>

<router-outlet></router-outlet>

<footer class="footer">
  <div class="container has-text-centered">
    <div class="content">
      From Croatia with ❤️
    </div>
  </div>
</footer>
```

The important part to note here is the use of `*ngIf="!authService.isAuthenticated"` to show/hide the navigation links based on the fact if the user is logged in or not.

The only thing we need to do in the 'code' file is to make sure we import the AuthService via the constructor: `constructor(private authService: AuthService) { }`.

#### app.module.ts
```
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { RouterModule } from '@angular/router';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';

import { AppComponent } from './app.component';
import { HomeComponent } from './home/home.component';
import { LoginComponent } from './login/login.component';
import { MembersComponent } from './members/members.component';

import { AuthService } from './auth.service';
import { AuthInterceptorService } from './auth-interceptor.service';
import { CanActivateViaAuthGuard } from './can-activate-via-auth.guard';

const routes = [
    { path: 'login', component: LoginComponent },
    {
        path: 'members',
        component: MembersComponent,
        canActivate: [
            CanActivateViaAuthGuard
        ]
    },
    { path: '', component: HomeComponent },
    { path: '**', redirectTo: '' }
];

@NgModule({
    declarations: [
        AppComponent,
        HomeComponent,
        LoginComponent,
        MembersComponent
    ],
    imports: [
        BrowserModule,
        FormsModule,
        ReactiveFormsModule,
        HttpClientModule,
        RouterModule.forRoot(routes)
    ],
    providers: [
        AuthService,
        {
            provide: HTTP_INTERCEPTORS,
            useClass: AuthInterceptorService,
            multi: true
        },
        CanActivateViaAuthGuard
    ],
    bootstrap: [AppComponent]
})
export class AppModule { }
```

This file imports all the components that we're using. As you can see, in the 'declarations' we list the components that we're using, the `imports` contain imported components for working with forms or sending HTTP requests.

#### guards and interceptors

Finally, you may notice something new in the `providers` array, where with the usual `AuthService` we have two additional things defined (an interceptor service and an auth guard):

```
{
    provide: HTTP_INTERCEPTORS,
    useClass: AuthInterceptorService,
    multi: true
},
CanActivateViaAuthGuard
```

The interceptor service has one task: to intercept every request that goes from the app and add the token to that request in its header:

```
import { Injectable, Injector } from '@angular/core';
import { HttpInterceptor } from '@angular/common/http';
import { AuthService } from './auth.service';

@Injectable()
export class AuthInterceptorService implements HttpInterceptor {

    constructor(private injector: Injector) { }

    intercept(req, next) {
        const authService = this.injector.get(AuthService);
        const authRequest = req.clone({
            // tslint:disable-next-line:max-line-length
            headers: req.headers.set('Authorization', 'Bearer ' + authService.token)
        });

        return next.handle(authRequest);
    }
}
```

THe guard is also simple and it's defined like this:

```
import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { Observable } from 'rxjs/Observable';
import { AuthService } from './auth.service';

@Injectable()
export class CanActivateViaAuthGuard implements CanActivate {
    constructor(private authService: AuthService) {

    }

    canActivate() {
        return this.authService.isAuthenticated;
    }
}
```

So, we define the so-called 'canActivate' guard which we use when we want to prevent the user from going to some route in the app to which he doesn't have the access. We use this guard in the route definition to prevent the user from going to the `/members` link if he's not logged in:

```
const routes = [
    { path: 'login', component: LoginComponent },
    {
        path: 'members',
        component: MembersComponent,
        canActivate: [
            CanActivateViaAuthGuard
        ]
    },
    { path: '', component: HomeComponent },
    { path: '**', redirectTo: '' }
];
```

When you have all of this wired up (and a Go program running locally), you should see:

![](https://i.imgur.com/7Dk3EJ7.gif)

## Conclusion
We've covered a lot of ground in this long post:

+ we learned a bit about how JWTs work
+ we created our own JWT with code examples in JavaScript and Go
+ we made a full-fledged app with Angular 5 on the frontend and Go on the backend that uses JWTs for authentication
+ we made use of Angulars Guards and Interceptors

I hope this was enough to get you started and build upon this example.

If you have any questions, feel free to reach out in the comments.
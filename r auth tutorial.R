#### Authentication
require(devtools)
require(httr)
require(httpuv)
require(googleCloudStorageR)
require(rlang)
require(plyr)
require(jsonlite)
require(data.table)

oauth_app <- function (appname, key, secret = NULL, redirect_uri = oauth_callback()){
  # appname = "google"
  # key = client.id
  # secret = client.secret
  if (missing(secret)) {
    env_name <- paste0(toupper(appname), "_CONSUMER_SECRET")
    secret <- Sys.getenv(env_name)
    if (secret == "") {
      warning("Couldn't find secret in environment variable ", 
              env_name, call. = FALSE)
      secret <- NULL
    }
    else {
      message("Using secret stored in environment variable ", 
              env_name)
    }
  }
  structure(list(appname = appname, secret = secret, key = key, 
                 redirect_uri = redirect_uri), class = "oauth_app")
}

#### Cryptograph 
nonce <- function(length = 10) { 
  paste(sample(c(letters, LETTERS, 0:9), length, replace = TRUE), collapse = "") 
}

init_oauth2.0.1 <- function (endpoint, app, scope = NULL, user_params = NULL, type = NULL, 
                             use_oob = getOption("httr_oob_default"), is_interactive = interactive(), 
                             use_basic_auth = FALSE) {

  if (!use_oob && !is_installed("httpuv")) {
    message("httpuv not installed, defaulting to out-of-band authentication")
    use_oob <- TRUE
  }
  if (isTRUE(use_oob)) {
    stopifnot(interactive())
    redirect_uri <- "urn:ietf:wg:oauth:2.0:oob"
    state <- NULL
  } else {
    redirect_uri <- oauth_callback()
    state <- nonce()
    print(state)
  }
  scope_arg <- paste(scope, collapse = " ")
  authorize_url <- modify_url(endpoint$authorize, query = compact(list(client_id = app$key, 
                                                                       scope = scope_arg, redirect_uri = redirect_uri, response_type = "code", 
                                                                       state = state)))
  print(authorize_url)
  if (isTRUE(use_oob)) {
    code <- oauth_exchanger(authorize_url)$code
  }
  else {
    code <- oauth_listener(authorize_url, is_interactive)$code
  }
  req_params <- list(client_id = app$key, redirect_uri = redirect_uri, 
                     grant_type = "authorization_code", code = code)
  if (!is.null(user_params)) {
    req_params <- utils::modifyList(user_params, req_params)
  }
  if (isTRUE(use_basic_auth)) {
    req <- POST(endpoint$access, encode = "form", body = req_params, 
                authenticate(app$key, app$secret, type = "basic"))
  }
  else {
    req_params$client_secret <- app$secret
    req <- POST(endpoint$access, encode = "form", body = req_params)
  }
  stop_for_status(req, task = "get an access token")
  content(req, type = type)
}

#### Refresh Token
oauth2.0_refresh <- function(endpoint, app, auth_token, type = NULL) {
  req <- POST(
    url = endpoint$access,
    multipart = FALSE,
    body = list(
      client_id = app$key,
      client_secret = app$secret,
      grant_type = "refresh_token",
      refresh_token = auth_token
    )
  )
  content_out <- content(req, type = type)
  content_out <- c(content_out, auth_token)
}


# Create new token, and append to token list if it exists
# client.id <- ""
# client.secret <- ""
# scope <- "https://www.googleapis.com/auth/dfatrafficking"

client.id = ""
client.secret = ""
scope = "https://www.googleapis.com/auth/dfatrafficking"

create_newToken <- function(client.id, client.secret, scope = NULL, cred_name = NULL, refresh = FALSE, refresh_token = NULL, token_list = NULL){
  if(length(scope)>=2){
    stop("Scope must be length of 1")
  }
  if(refresh){
    auth_refresh <- oauth2.0_refresh(endpoint = oauth_endpoints("google"),
                                     app = oauth_app(appname = "google", key = client.id, secret = client.secret),
                                     auth_token = refresh_token)
    return(auth_refresh)
  } else {
    auth_token <- init_oauth2.0.1(endpoint = oauth_endpoints("google"),
                                  app = oauth_app(appname = "google", 
                                                  key = client.id, 
                                                  secret = client.secret),
                                  scope = scope,
                                  is_interactive = interactive(), use_basic_auth =  F, use_oob =  F)
    if(!is.null(token_list) && !is.null(cred_name)){
      e <- parent.env(environment())
      token[[cred_name]] <- auth_token
      e$token <- token
    }
    return(auth_token)
  }
}

#### GCS FUNCTIONS
get_google_creds <- function(gcs_creds_file){
  gcs_auth(gcs_creds)
  creds <- gcs_get_object(bucket = "xax-configs", object_name = "google/google.tokens.json")
  return(creds[[token]])
}

get_gcs_object <- function(bucket, object_x, gcs_creds){
  gcs_auth(gcs_creds)
  list_files <- gcs_list_objects(bucket = bucket)
  x <- gcs_get_object(list_files[which(list_files$name==object_x),"name"], parseObject = F, bucket = bucket)
  return(rawToChar(x$content))
}

### Upload to bucket
put_gcs_object <- function(file, bucket, obj_name, gcs_creds, subdir = NULL){
  gcs_auth(gcs_creds)
  x <- gcs_upload(file, bucket = bucket , name = paste0(subdir,"",obj_name))
  print(x)
  return(x)
}

### Example ###
## Static variables
gcs_creds <- "C:/Users/SP/Documents/gcp_library/r-scripts/google_credential.json"
tokens <- get_gcs_object(bucket = 'xax-configs', object_x = "google/google.tokens.json", gcs_creds = gcs_creds)
tokens <- fromJSON(tokens)

### Authentication Part ### 
my_token <- create_newToken(client.id = "",
                     client.secret = "",
                     scope = "https://www.googleapis.com/auth/dfatrafficking")

## add in our client.id and client.secret
my_token$client.id <- ""
my_token$client.secret <- ""


### now append
tokens[["test_token"]] <- my_token ## Append


tokens <- RJSONIO::toJSON(tokens, pretty = T) ## always try to make it pretty! Also make sure to use RJSONIO
## You can use cat() to see how it looks. Print won't show the special characters like \n or \t
cat(RJSONIO::toJSON(tokens, pretty = T))

## now write the file
fname <- "C:/tmp/test_token.json"
write(x = tokens, file = fname)


## next is putting the json file to our xax-configs
## This is uploading to the cloud storage!
put_gcs_object(file = fname, obj_name = "test_tokens.json", bucket = "xax-configs", gcs_creds = gcs_creds)

### refresh the token
refreshed_token <- create_newToken(refresh = TRUE, 
                refresh_token = my_token$refresh_token, 
                client.id = "",
                client.secret = "")




### Downloading the report part ###
## https://dfareporting.googleapis.com/dfareporting/v3.4/userprofiles/{profileId}/reports/{reportId}/files
## We need to do a GET request to the api
## your token access_token will need to be put in beside the "bearer" just like in python
## Your token is the "Access Token" within the tokens. That would be **refreshed_token$access_token**
## Now we need to prepare the url by replacing profileid and reportid
## ill use these as example:
profile_id = "5462937"
report_id = "733270763"
url <- "https://dfareporting.googleapis.com/dfareporting/v3.4/userprofiles/{profileId}/reports/{reportId}/files"
url <- gsub("\\{profileId\\}", profile_id, url) ## {} are special characters so you need to use \\ to state they are literal characters
url <- gsub("\\{reportId\\}", report_id, url)

binary.data <- GET(url,
                   config = add_headers("Authorization" = sprintf("Bearer %s", refreshed_token$access_token),
                                        "Content-Type" = "application/json"),                  
                   verbose())
data <- content(binary.data, "text")
data <- jsonlite::fromJSON(data)

## Now you noticed that the data is denied. That is because its the wrong scope. 
## You can see that we used "https://www.googleapis.com/auth/dfatrafficking" as our scope.
## Apparently, dfatracking and dfareporting is different. 
## So now you have to make a different token with the correct scope.
## This is the correct scope. https://www.googleapis.com/auth/dfareporting. 
## If you don't know, always check the documentation in the google api reference website. 


my_token <- create_newToken(client.id = "",
                            client.secret = "",
                            scope = "https://www.googleapis.com/auth/dfareporting")

refreshed_token <- create_newToken(refresh = TRUE, 
                                   refresh_token = my_token$refresh_token, 
                                   client.id = "",
                                   client.secret = "")

url <- "https://dfareporting.googleapis.com/dfareporting/v3.4/userprofiles/{profileId}/reports/{reportId}/files"
url <- gsub("\\{profileId\\}", profile_id, url) ## {} are special characters so you need to use \\ to state they are literal characters
url <- gsub("\\{reportId\\}", report_id,url)
binary.data <- GET(url,
                   config = add_headers("Authorization" = sprintf("Bearer %s", refreshed_token$access_token)),                  
                   verbose())
data <- content(binary.data, "text")
data <- jsonlite::fromJSON(data) ## The important data here is in data$items$id, specifically the first row



x <- GET(url = data$items$urls$apiUrl[1], 
    config = add_headers("Authorization" = sprintf("Bearer %s", my_token$access_token)))



x <- content(x, "text") ## convert to readable string


## This is most likely going to have a bad output. Watch.
df <- fread(x)
View(df) ### Oh no. Its not reading properly.


### Let's see why
tmp_file <- "C:/tmp/temp.csv"
write(x, tmp_file)


s <- readLines(tmp_file) ### fine "report fields"
df <- fread(tmp_file, skip = which(s=="Report Fields"))
### Then you're done! You can now just push this data to the process and then us put_gcs_object() to send it to the cloud storage



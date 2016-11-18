# steam_auth

Fork of [steam_go](https://github.com/solovev/steam_go) to use [fasthttp](https://github.com/valyala/fasthttp)

### Example
```
package main

import (
	"net/http"

	"github.com/solovev/steam_go"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	opId := steam_auth.NewOpenId(r)
	switch opId.Mode() {
	case "":
		http.Redirect(w, r, opId.AuthUrl(), 301)
	case "cancel":
		w.Write([]byte("Authorization cancelled"))
	default:
		steamId, err := opId.ValidateAndGetId()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		//
		//	Do smth with steamId
		//
		w.Write([]byte(steamId))
	}
}

func main() {
	http.HandleFunc("/login", loginHandler)
	http.ListenAndServe(":8080", nil)
}
```
# steam_auth

Fork of [steam_go](https://github.com/solovev/steam_go) to use [fasthttp](https://github.com/valyala/fasthttp)

### Example
``` go
import (
	"net/http"

	"github.com/mbcrocci/steam_go"
)

func loginHandle(ctx *fasthttp.RequestCtx)
	opID, err := steam_auth.NewOpenId(ctx)
	if err != nil {
		// handle the error properly
		return
	}
	switch opID.Mode() {
	case "":
		ctx.Redirect(opID.AuthUrl(), 301)
	case "cancel":
		fmt.FPrintf(ctx, "Authorization cancelled")
	default:
		steamID, err := opID.ValidateAndGetId()
		if err != nil {
			// do something instead of returning
			return
		}
	}
}
```

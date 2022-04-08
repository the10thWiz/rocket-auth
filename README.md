# Rocket Auth

Secure and safe user authenticaiton for the Rocket web framework.

## Design

This crate strives to be as safe and secure as possible, while also being easy to
use. To this end, I provide several safe wrapper types, which can directly be deserialized
from Rocket input, and don't provide any methods to access the contained user secrets.
Therefore they don't implment the `Debug` trait since it could encourage logging
passwords or other user secrets.

I want to make supporting both OAuth and Password based authentication transparently.
However, this doesn't really work, since OAuth and Passwords are different; OAuth
doesn't really differentiate between account creation and account login: the only
difference is whether they are in the password database. I likely need to change
the `UserDb` trait to better match this, although I would also prefer to avoid adding
methods.

## User Database

Obviously, the user needs to provide a UserDatabase implementation. We can likely
provide macros to handle writing the wrapper code, although this is a stretch goal.
To make implmenting the `UserDb` trait easier, I need to simplify the set of operations
the DB needs to implement. What makes this harder is my desire to support arbitrary
User info structs.

### UserId

I need to come up with a unified UserId type. First, it needs to be general enough
to handle both OAuth (potentially with multiple providers), and simple enough that
the same party can always create the UserId. To support OAuth properly, I likely
want this crate to create the UserId, with no input from the crate's consumer. This
becomes trivial for OAuth, since most OAuth providers already assign a unique ID
to each user, which I can just compose with a marker to indicate which provider the
ID is from. For password auth, the ideal solution would be the same, where I assign
a unique ID, but I don't have direct access to the DB, so the best option here is
likely a random id. This may not be an issue (something like a GUID should work),
but I'm not sure how (or if) I should handle the possibility of collisions. This
also complicates pasword auth since the user most likely supplies a username or email,
not a user id. I could take an extra step to look up the username/email, and find
the associated id, but this requires me to complicate the `UserDb` trait. I think
this may be the best option, but I'm not sure whether it should be two methods (i.e.
`lookup_by_id` & `lookup_by_username`), or a single method (i.e. `lookup(Either<Username,
UserId>)`). I'm leaning towards the single method, but I will want to provide some
custom Either implementation that provides some convience methods.

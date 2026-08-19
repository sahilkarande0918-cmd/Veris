# Can Veris read your SMS automatically?

Short answer: **technically yes, and we deliberately do not.** This document
records what we checked and why we chose what we chose, because "we couldn't"
and "we decided not to" are very different answers to a judge.

## What Google Play actually says

`READ_SMS` and `RECEIVE_SMS` are *restricted* permissions. The rule is not
"never" -- it is that an app may only request them while it is **actively
registered as the device's default SMS, Phone, or Assistant handler**, and it
must stop using them the moment it stops being the default. An app that is not
a default handler "may not declare use of the above permissions in the
manifest, including placeholder text".

Fraud and spam detection *is* an approved use for a default handler. That is
exactly how Truecaller does it.

Source: [Use of SMS or Call Log permission groups](https://support.google.com/googleplay/android-developer/answer/10208820),
[Permissions and APIs that Access Sensitive Information](https://support.google.com/googleplay/android-developer/answer/16558241).

## The four routes, and what each one costs

| Route | Permission needed | Can it read a scam SMS? | Cost |
|---|---|---|---|
| **Share sheet** (what Veris uses) | none | yes, any message | one tap by the user |
| **SMS User Consent API** | none | only OTP-shaped messages | useless for scam text |
| **SMS Retriever API** | none | only messages containing our app hash | useless here |
| **Default SMS handler** | `READ_SMS` | yes, all messages, automatically | Veris must *replace* the user's messaging app |

### Why not SMS Retriever or User Consent

Both exist for one job: reading a one-time code your own server just sent. The
Retriever API only surfaces messages ending in your app's hash. The User
Consent API only matches a message containing a 4-10 character code, within a
five-minute window, and not from a contact.

A scam SMS is none of those things. Reaching for these APIs would look
compliant while detecting nothing.

Source: [SMS Retriever](https://developers.google.com/identity/sms-retriever/overview),
[SMS User Consent](https://developers.google.com/identity/sms-retriever/user-consent/overview).

### Why not the default-handler route

It is legitimate and it would work. It also means building and maintaining a
full SMS client -- conversation list, sending, MMS, RCS, delivery reports,
dual SIM, backup -- because the user gives up their existing messaging app to
get it. And in exchange for checking a link, Veris would be able to read every
message the user ever receives.

That trade is wrong for this product, and it is a bad answer in a room full of
people asking about privacy. We are a verification tool, not a messaging app.

## What Veris does instead

Long-press the message, Share, choose Veris. It is one extra tap, it works
today, it works for WhatsApp and email and any other app, and no app gains
standing access to the user's messages.

The app says this in plain words on the Protection screen rather than hiding
it, because a user who wonders "why doesn't it just read my texts?" deserves
the real answer.

## The sideload demo build

The original build spec allows an SMS-screening demo on a **sideloaded**,
clearly-labelled build. We have not shipped one. The share-sheet path already
demonstrates the detection end to end on real messages, so a second intake
path would add restricted permissions to the repo for no new capability --
and a `READ_SMS` string sitting in the manifest is exactly what gets a Play
submission rejected later.

If you do want it for a specific demo, the honest way is a separate build
flavour that is never uploaded to Play, with the permission added by a config
plugin guarded on an env var, so the Play-facing build cannot pick it up by
accident.

## What we do read

Nothing, in the background. Veris only ever sees:

- text you paste,
- text you share into it,
- the phone number of a call currently ringing, if you turn on call screening
  (that is `CallScreeningService`, which needs no `READ_CALL_LOG` and cannot
  see your call history).

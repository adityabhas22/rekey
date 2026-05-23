-- rekey-mail-handler.applescript
--
-- Apple Mail.app rule handler. Posts each incoming message to the rekey
-- localhost receiver so OTP / reset-link emails can be captured by the
-- agent in real time.
--
-- Installation: open Mail.app → Mail → Settings → Rules → Add Rule.
--   Condition: Every Message.
--   Action:    Run AppleScript → choose this file.
--
-- After saving, Mail.app moves the script to
--   ~/Library/Application Scripts/com.apple.mail/
--
-- The receiver runs at http://127.0.0.1:7777/mail-event while rekey is
-- active. Messages that arrive while rekey is not running are simply not
-- seen (which is intentional — we only care during a rotation).

using terms from application "Mail"
    on perform mail action with messages msgs for rule r
        repeat with m in msgs
            try
                set theSender to sender of m as string
            on error
                set theSender to ""
            end try
            try
                set theSubject to subject of m as string
            on error
                set theSubject to ""
            end try
            try
                set theBody to content of m as string
            on error
                set theBody to ""
            end try
            -- Trim body to ~4000 chars to keep the POST snappy.
            if length of theBody > 4000 then
                set theBody to text 1 thru 4000 of theBody
            end if

            try
                do shell script "curl -s -m 3 -X POST http://127.0.0.1:7777/mail-event " & ¬
                    "--data-urlencode 'from=' --data-urlencode " & ¬
                    "from=" & quoted form of theSender & " " & ¬
                    "--data-urlencode subject=" & quoted form of theSubject & " " & ¬
                    "--data-urlencode body=" & quoted form of theBody
            on error errMsg
                -- Silent failure (e.g. rekey not running). Don't bother the user.
            end try
        end repeat
    end perform mail action with messages
end using terms from

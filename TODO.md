
# Enhancements

* Allocate aligned memory which we mark with mlock()
* Clear all passwords currently in clear text if the computer goes in hibernation
  (see https://askubuntu.com/questions/183516/how-do-i-detect-when-my-system-wakes-up-from-suspend-via-dbus-or-similar-in-a-py/184046#184046
  for code in python that is capable of capturing the "PrepareForSleep" event
  before entering freeze mode)
* Use open()/read()/write()/close() directly to avoid as many buffers as
  possible (although this only deals with encrypted passwords so it is already
  pretty safe)


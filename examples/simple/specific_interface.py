import telepot
from telepot.api import set_interface, set_source_address

# Define which interface name or IP address you want to use
lan_interface = 'eth0'
lan_ip = "192.168.1.2"

# Define user specific bot parameters
api_token = "5555555555:AAAAAAAAAA_AAAAAAAAAAAAA_AAAAAAAAAA"  # Replace with your Bot's API token
chat_id = 5555555555  # Replace with your chat_id

# Define the interface that the Bot should use
# bot = telepot.Bot(api_token, interface=lan_interface)

# Alternatively, don't specify the interface on the bot and define it in the API instead
bot = telepot.Bot(api_token)
set_interface(lan_interface)

# Alternatively, specify the IP address of the desired interface instead of interface name
# set_source_address(lan_ip)

bot.sendMessage(chat_id, "Hello World!")
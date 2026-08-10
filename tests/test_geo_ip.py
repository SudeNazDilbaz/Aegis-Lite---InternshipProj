from aegis_lite.geo_ip import get_ip_location


print("========== GEOIP TEST ==========\n")

# Public IP test
public_ip = "8.8.8.8"
public_result = get_ip_location(public_ip)

print("Public IP Test")
print(f"IP        : {public_result['ip']}")
print(f"Country   : {public_result['country']}")
print(f"City      : {public_result['city']}")
print(f"Latitude  : {public_result['latitude']}")
print(f"Longitude : {public_result['longitude']}")


invalid_ip = "999.999.999.999"
invalid_result = get_ip_location(invalid_ip)

print("\nInvalid IP Test")
print(f"IP        : {invalid_result['ip']}")
print(f"Country   : {invalid_result['country']}")
print(f"City      : {invalid_result['city']}")
print(f"Latitude  : {invalid_result['latitude']}")
print(f"Longitude : {invalid_result['longitude']}")

print("\nReserved IP Test")

reserved_ip = "198.51.100.40"
reserved_result = get_ip_location(reserved_ip)

print(f"IP        : {reserved_result['ip']}")
print(f"Country   : {reserved_result['country']}")
print(f"City      : {reserved_result['city']}")
print(f"Latitude  : {reserved_result['latitude']}")
print(f"Longitude : {reserved_result['longitude']}")
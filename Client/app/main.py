from machine import get_machine_hash
from license_manager import verify_license

def main():
    machine_hash = get_machine_hash()

    print("\n=== ACTIVATION REQUIRED ===\n")
    print("Machine Hash:\n")
    print(machine_hash)
    print("\nSend this hash to vendor to receive license.\n")

    while True:
        license_key = input("Enter License Key: ").strip()

        result = verify_license(machine_hash, license_key)

        if result.is_valid:
            print(f"\n✅ {result.message}\n")
            break
        else:
            print(f"\n❌ {result.message}\n")


if __name__ == "__main__":
    main()

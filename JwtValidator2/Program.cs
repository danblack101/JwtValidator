
namespace JwtValidator2
{
    class Program
    {
        static void Main(string[] args)
        {
            var token = Encoder.Encode();
            Deocder.Decode(token);
        }
    }
}

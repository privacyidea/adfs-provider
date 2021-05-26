using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SDK
{
    public class PIChallenge
    {
        public string Serial { get; set; } = "";
        public string Message { get; set; } = "";
        public string TransactionID { get; set; } = "";
        public string Type { get; set; } = "";
        public List<string> attributes { get; set; } = new List<string>();
    }
}

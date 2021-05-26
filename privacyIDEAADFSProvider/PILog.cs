using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SDK
{
    public interface PILog
    {
        void Log(string message);

        void Error(string message);

        void Error(Exception exception);
    }
}

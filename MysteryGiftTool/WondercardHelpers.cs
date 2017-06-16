using PKHeX.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MysteryGiftTool
{
    public class WondercardHelpers
    {
        public static string getDescription(MysteryGift gift)
        {            
            if (gift.Empty)
                return "Empty Slot. No data!";

            var gameStrings = new GameInfo.GameStrings("en");

            string s = gift.getCardHeader() + Environment.NewLine;
            if (gift.IsItem)
            {
                s += "Item: " + gameStrings.itemlist[gift.Item] + Environment.NewLine + "Quantity: " + gift.Quantity + Environment.NewLine;
            }
            else if (gift.IsPokémon)
            {
                var pk = gift.convertToPKM(new SAV7());

                try
                {
                    s += $"{gameStrings.specieslist[pk.Species]} @ {gameStrings.itemlist[pk.HeldItem]}  --- ";
                    s += (pk.IsEgg ? gameStrings.eggname : $"{pk.OT_Name} - {pk.TID:00000}/{pk.SID:00000}") + Environment.NewLine;
                    s += $"{gameStrings.movelist[pk.Move1]} / {gameStrings.movelist[pk.Move2]} / {gameStrings.movelist[pk.Move3]} / {gameStrings.movelist[pk.Move4]}" + Environment.NewLine;
                    if (gift is WC7)
                    {
                        var addItem = ((WC7)gift).AdditionalItem;
                        if (addItem != 0)
                            s += $"+ {gameStrings.itemlist[addItem]}" + Environment.NewLine;
                    }
                }
                catch { s += "Unable to create gift description." + Environment.NewLine; }
            }
            else { s += "Unknown Wonder Card Type!" + Environment.NewLine; }
            if (gift is WC7)
            {
                var wc7 = (WC7)gift;
                s += $"Repeatable: {wc7.GiftRepeatable}" + Environment.NewLine;
                s += $"Collected: {wc7.GiftUsed}" + Environment.NewLine;
                s += $"Once Per Day: {wc7.GiftOncePerDay}" + Environment.NewLine;
            }
            return s;
        }
    }
}
